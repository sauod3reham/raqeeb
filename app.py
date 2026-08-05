import streamlit as st
from src.config import OPENAI_API_KEY, CURRENT_COMPLIANCE_YEAR
from src.rag.ingest import ensure_vector_store
from src.rag.loaders import read_knowledge_files, read_pdf_text
from src.services.product_pipeline import run_audit
from src.services.standards_catalog import get_frameworks, get_perspectives, get_standards
from src.llm.client import analyze_image_evidence
from src.llm.prompts import build_image_evidence_prompt

st.set_page_config(page_title="Digital Transformation Compliance Auditor", layout="wide")

st.title("مساعد تدقيق الامتثال التنظيمي")
st.write(
    "مساعد ذكي لتدقيق امتثال الجهات للمتطلبات التنظيمية (مثل معايير قياس التحول الرقمي، والضوابط الأساسية "
    "للأمن السيبراني ECC)، من خلال تحليل الملفات والصور المرفوعة، وقياس درجة الامتثال، وتحديد الفجوات والتوصيات.")

if not OPENAI_API_KEY:
    st.warning("الرجاء إعداد OPENAI_API_KEY في ملف .env أو كمتغير بيئة لاستخدام نموذج OpenAI.")

with st.expander("عن المنتج"):
    st.write(
        "يعتمد النظام على قاعدة معرفة تضم نصوص الأطر التنظيمية، ويستخدم بحث RAG لمطابقة محتوى الملف المرفوع "
        "مع متطلبات المعيار المحدد، بالإضافة إلى تحليل أي أدلة إثبات مصورة (لقطات شاشة) بواسطة نموذج رؤية "
        f"للتحقق من ملاءمتها للمعيار ومن كونها محدثة بتاريخ عام {CURRENT_COMPLIANCE_YEAR} لقياس الامتثال الحالي، "
        "ثم يصدر تقييم امتثال وفجوات وتوصيات وتقرير CSV.")

st.subheader("1. تحديد الإطار التنظيمي والمعيار")
frameworks = get_frameworks()
framework_labels = {key: label for key, label in frameworks}
selected_framework_key = st.selectbox(
    "الإطار التنظيمي",
    options=[key for key, _ in frameworks],
    format_func=lambda key: framework_labels[key],
)
selected_perspective = st.selectbox("المنظور / المحور", get_perspectives(selected_framework_key))
standards = get_standards(selected_framework_key, selected_perspective)
standard_labels = [f"{sid} - {title}" for sid, title in standards]
selected_label = st.selectbox("المعيار / الضابط", standard_labels)
selected_standard_id, selected_standard_title = standards[standard_labels.index(selected_label)]
selected_framework_label = framework_labels[selected_framework_key]

st.subheader("2. رفع الوثيقة المطلوب تدقيقها")
uploaded_file = st.file_uploader("ارفع وثيقة PDF للتدقيق", type=["pdf"])
if uploaded_file is not None:
    try:
        default_text = read_pdf_text(uploaded_file)
    except Exception as exc:
        st.error(f"تعذّرت قراءة ملف PDF: {exc}")
        default_text = ""
else:
    default_text = ""

proposal_text = st.text_area("نص الوثيقة (يمكن تعديله أو لصق النص مباشرة)", value=default_text, height=220)

st.subheader("3. رفع أدلة الإثبات المصورة (اختياري)")
st.caption(
    f"يمكن رفع لقطات شاشة أو صور مستندات كأدلة إثبات. سيتحقق النظام من مطابقتها للمعيار المختار، "
    f"ومن وجود تاريخ ظاهر ضمن عام {CURRENT_COMPLIANCE_YEAR} لاعتبارها دليلاً محدثاً."
)
uploaded_images = st.file_uploader(
    "أدلة إثبات مصورة (PNG / JPG)",
    type=["png", "jpg", "jpeg"],
    accept_multiple_files=True,
)

if uploaded_images and st.button("تحليل الأدلة المصورة"):
    vision_prompt = build_image_evidence_prompt(selected_standard_id, selected_standard_title)
    results = {}
    for img_file in uploaded_images:
        with st.spinner(f"جارٍ تحليل الصورة: {img_file.name} ..."):
            img_bytes = img_file.getvalue()
            mime_type = img_file.type or "image/png"
            try:
                results[img_file.name] = analyze_image_evidence(img_bytes, mime_type, vision_prompt)
            except Exception as exc:
                results[img_file.name] = f"تعذّر تحليل الصورة: {exc}"
    st.session_state["image_evidence_results"] = results

image_evidence_notes = []
if st.session_state.get("image_evidence_results"):
    st.markdown("**نتائج تحليل الأدلة المصورة:**")
    for name, analysis_text in st.session_state["image_evidence_results"].items():
        with st.expander(f"🖼️ {name}"):
            st.write(analysis_text)
        image_evidence_notes.append(f"({name}) {analysis_text}")

col1, col2 = st.columns([1, 1])
with col1:
    if st.button("تحضير قاعدة المعرفة"):
        st.info("يجري تحضير قاعدة المعرفة الآن...")
        ensure_vector_store()
        st.success("تم تحضير قاعدة المعرفة بنجاح.")

with col2:
    if st.button("تشغيل تدقيق الامتثال"):
        if not proposal_text.strip() and not image_evidence_notes:
            st.error("الرجاء رفع وثيقة أو صورة دليل أو إدخال نصها للتدقيق.")
        elif not OPENAI_API_KEY:
            st.error("مفتاح OpenAI مفقود. الرجاء إضافة OPENAI_API_KEY.")
        else:
            with st.spinner(f"جارٍ تدقيق الوثيقة مقابل المعيار {selected_standard_id}..."):
                result = run_audit(
                    proposal_text,
                    user_request="",
                    standard_id=selected_standard_id,
                    standard_title=selected_standard_title,
                    framework_label=selected_framework_label,
                    image_evidence_notes=image_evidence_notes or None,
                )
                st.subheader("نتائج التدقيق")
                st.write(result.get("final_answer"))
                if result.get("report_csv"):
                    st.download_button(
                        label="تنزيل تقرير CSV للامتثال",
                        data=result["report_csv"],
                        file_name=f"compliance_report_{selected_standard_id}.csv",
                        mime="text/csv",
                    )

if st.checkbox("عرض أساس المعرفة"):
    st.subheader("المحتوى الموجود في قاعدة المعرفة")
    st.write("تستخدم قاعدة المعرفة المتطلبات التالية لربط نتائج التدقيق بالأدلة.")

    files = read_knowledge_files()
    for item in files:
        st.markdown(f"**{item['source']}**")
        st.write(item["text"])
