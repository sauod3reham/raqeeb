import streamlit as st
from src.config import (
    OPENAI_API_KEY,
    CURRENT_COMPLIANCE_YEAR,
    AUDIT_RATE_LIMIT_MAX,
    AUDIT_RATE_LIMIT_WINDOW_SECONDS,
    IMAGE_RATE_LIMIT_MAX,
    IMAGE_RATE_LIMIT_WINDOW_SECONDS,
)
from src.rag.ingest import ensure_vector_store
from src.rag.loaders import read_knowledge_files, read_pdf_text
from src.services.product_pipeline import run_audit
from src.services.standards_catalog import get_frameworks, get_perspectives, get_standards
from src.llm.client import analyze_image_evidence
from src.llm.prompts import build_image_evidence_prompt
from src.security.auth import AUTH_ENABLED, verify_credentials, has_permission, users_file_exists
from src.security.file_validation import (
    validate_pdf_upload,
    validate_image_upload,
    sanitize_plain_text,
    MAX_TEXT_LEN,
    MAX_IMAGES_PER_REQUEST,
)
from src.security.rate_limit import check_rate_limit
from src.security.audit_log import log_event, new_correlation_id

st.set_page_config(page_title="Digital Transformation Compliance Auditor", layout="wide")

# ----------------------------------------------------------------------------
# Auth gate (server-side; Streamlit executes this script entirely on the
# server per session, so there is no client-only equivalent to bypass).
# ----------------------------------------------------------------------------
if "auth_role" not in st.session_state:
    st.session_state["auth_role"] = None
    st.session_state["auth_user"] = None
if "correlation_id" not in st.session_state:
    st.session_state["correlation_id"] = new_correlation_id()

if AUTH_ENABLED and not st.session_state["auth_role"]:
    st.title("تسجيل الدخول")
    if not users_file_exists():
        st.info(
            "لا يوجد مستخدمون بعد. أنشئ أول حساب Admin من الطرفية عبر:\n\n"
            "python scripts/manage_users.py add <username> admin"
        )
    with st.form("login_form"):
        username = st.text_input("اسم المستخدم", max_chars=100)
        password = st.text_input("كلمة المرور", type="password", max_chars=200)
        submitted = st.form_submit_button("دخول")
    if submitted:
        role = verify_credentials(username, password)
        if role:
            st.session_state["auth_role"] = role
            st.session_state["auth_user"] = username
            log_event(
                event="login", correlation_id=st.session_state["correlation_id"],
                user=username, role=role, result="success",
            )
            st.rerun()
        else:
            log_event(
                event="login", correlation_id=st.session_state["correlation_id"],
                user=sanitize_plain_text(username, 100), result="failed",
            )
            st.error("بيانات الدخول غير صحيحة.")
    st.stop()

current_user = st.session_state.get("auth_user") or "local"
current_role = st.session_state.get("auth_role") or "admin"  # unrestricted when AUTH_ENABLED=false
correlation_id = st.session_state["correlation_id"]

with st.sidebar:
    if AUTH_ENABLED:
        st.write(f"👤 **{current_user}**")
        st.write(f"الدور: `{current_role}`")
        if st.button("تسجيل الخروج"):
            log_event(event="logout", correlation_id=correlation_id, user=current_user, role=current_role, result="success")
            st.session_state["auth_role"] = None
            st.session_state["auth_user"] = None
            st.rerun()
    else:
        st.caption("وضع التحقق من الهوية معطّل (AUTH_ENABLED=false) — للاستخدام المحلي فقط.")

# ----------------------------------------------------------------------------
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
        "ثم يصدر تقييم امتثال وفجوات وتوصيات وتقرير CSV. "
        "لا يُصدر النظام حكم امتثال دون دليل واضح؛ الحالات غير المدعومة تُصنَّف \"غير مثبت / يتطلب مراجعة بشرية\".")

if not has_permission(current_role, "view_knowledge_base"):
    st.error("لا تملك صلاحية استخدام هذه الأداة. يرجى التواصل مع مسؤول النظام.")
    st.stop()

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
default_text = ""
if uploaded_file is not None:
    file_bytes = uploaded_file.getvalue()
    is_valid, reason = validate_pdf_upload(file_bytes, uploaded_file.type or "")
    if not is_valid:
        st.error(f"تم رفض الملف: {reason}")
        log_event(
            event="file_upload_rejected", correlation_id=correlation_id, user=current_user, role=current_role,
            resource=uploaded_file.name, result="rejected", details=reason,
        )
    else:
        try:
            default_text = read_pdf_text(uploaded_file)
        except Exception:
            st.error("تعذّرت قراءة ملف PDF. تأكد من أن الملف غير تالف وأعد المحاولة.")
            log_event(
                event="file_processing_error", correlation_id=correlation_id, user=current_user, role=current_role,
                resource=uploaded_file.name, result="error",
            )

proposal_text = st.text_area(
    "نص الوثيقة (يمكن تعديله أو لصق النص مباشرة)",
    value=sanitize_plain_text(default_text, MAX_TEXT_LEN),
    height=220,
    max_chars=MAX_TEXT_LEN,
)

st.subheader("3. رفع أدلة الإثبات المصورة (اختياري)")
st.caption(
    f"يمكن رفع حتى {MAX_IMAGES_PER_REQUEST} لقطات شاشة أو صور مستندات كأدلة إثبات. سيتحقق النظام من مطابقتها "
    f"للمعيار المختار، ومن وجود تاريخ ظاهر ضمن عام {CURRENT_COMPLIANCE_YEAR} لاعتبارها دليلاً محدثاً."
)
uploaded_images = st.file_uploader(
    "أدلة إثبات مصورة (PNG / JPG)",
    type=["png", "jpg", "jpeg"],
    accept_multiple_files=True,
)
if uploaded_images and len(uploaded_images) > MAX_IMAGES_PER_REQUEST:
    st.error(f"الحد الأقصى لعدد الصور هو {MAX_IMAGES_PER_REQUEST} في كل مرة. تم أخذ أول {MAX_IMAGES_PER_REQUEST} فقط.")
    uploaded_images = uploaded_images[:MAX_IMAGES_PER_REQUEST]

if uploaded_images and st.button("تحليل الأدلة المصورة"):
    if not check_rate_limit("image_analysis", IMAGE_RATE_LIMIT_MAX, IMAGE_RATE_LIMIT_WINDOW_SECONDS):
        st.error("تم تجاوز الحد المسموح لعدد عمليات تحليل الصور خلال فترة قصيرة. حاول لاحقًا.")
        log_event(event="rate_limit_exceeded", correlation_id=correlation_id, user=current_user, role=current_role,
                   resource="image_analysis", result="blocked")
    else:
        vision_prompt = build_image_evidence_prompt(selected_standard_id, selected_standard_title)
        results = {}
        for img_file in uploaded_images:
            img_bytes = img_file.getvalue()
            is_valid, reason = validate_image_upload(img_bytes, img_file.type or "")
            if not is_valid:
                results[img_file.name] = f"⛔ تم رفض هذه الصورة: {reason}"
                log_event(
                    event="file_upload_rejected", correlation_id=correlation_id, user=current_user, role=current_role,
                    resource=img_file.name, result="rejected", details=reason,
                )
                continue
            with st.spinner(f"جارٍ تحليل الصورة: {img_file.name} ..."):
                mime_type = img_file.type or "image/png"
                try:
                    results[img_file.name] = analyze_image_evidence(img_bytes, mime_type, vision_prompt)
                    log_event(event="image_analysis", correlation_id=correlation_id, user=current_user,
                               role=current_role, resource=img_file.name, result="success")
                except Exception:
                    results[img_file.name] = "تعذّر تحليل هذه الصورة حاليًا. حاول مرة أخرى لاحقًا."
                    log_event(event="image_analysis", correlation_id=correlation_id, user=current_user,
                               role=current_role, resource=img_file.name, result="error")
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
    if not has_permission(current_role, "manage_knowledge_base"):
        st.caption("🔒 تحضير قاعدة المعرفة متاح فقط لدور Admin.")
    elif st.button("تحضير قاعدة المعرفة"):
        st.info("يجري تحضير قاعدة المعرفة الآن...")
        ensure_vector_store()
        st.success("تم تحضير قاعدة المعرفة بنجاح.")
        log_event(event="knowledge_base_prepared", correlation_id=correlation_id, user=current_user,
                   role=current_role, result="success")

with col2:
    if not has_permission(current_role, "run_audit"):
        st.caption("🔒 تشغيل تدقيق الامتثال متاح فقط لدوري Admin وComplianceAuditor.")
    elif st.button("تشغيل تدقيق الامتثال"):
        if not proposal_text.strip() and not image_evidence_notes:
            st.error("الرجاء رفع وثيقة أو صورة دليل أو إدخال نصها للتدقيق.")
        elif not OPENAI_API_KEY:
            st.error("مفتاح OpenAI مفقود. الرجاء إضافة OPENAI_API_KEY.")
        elif not check_rate_limit("audit_run", AUDIT_RATE_LIMIT_MAX, AUDIT_RATE_LIMIT_WINDOW_SECONDS):
            st.error("تم تجاوز الحد المسموح لعدد عمليات التدقيق خلال فترة قصيرة. حاول لاحقًا.")
            log_event(event="rate_limit_exceeded", correlation_id=correlation_id, user=current_user,
                       role=current_role, resource="audit_run", result="blocked")
        else:
            with st.spinner(f"جارٍ تدقيق الوثيقة مقابل المعيار {selected_standard_id}..."):
                try:
                    result = run_audit(
                        proposal_text,
                        user_request="",
                        standard_id=selected_standard_id,
                        standard_title=selected_standard_title,
                        framework_label=selected_framework_label,
                        image_evidence_notes=image_evidence_notes or None,
                        correlation_id=correlation_id,
                        user=current_user,
                        role=current_role,
                    )
                except Exception:
                    st.error("حدث خطأ غير متوقع أثناء التدقيق. تم تسجيل الحادثة داخليًا. حاول مرة أخرى لاحقًا.")
                    log_event(event="audit_run", correlation_id=correlation_id, user=current_user,
                               role=current_role, resource=f"standard={selected_standard_id}", result="error")
                    result = None
                if result:
                    st.subheader("نتائج التدقيق")
                    st.write(result.get("final_answer"))
                    if result.get("report_csv") and has_permission(current_role, "download_report"):
                        st.download_button(
                            label="تنزيل تقرير CSV للامتثال",
                            data=result["report_csv"],
                            file_name=f"compliance_report_{selected_standard_id}.csv",
                            mime="text/csv",
                        )

if has_permission(current_role, "view_knowledge_base") and st.checkbox("عرض أساس المعرفة"):
    st.subheader("المحتوى الموجود في قاعدة المعرفة")
    st.write("تستخدم قاعدة المعرفة المتطلبات التالية لربط نتائج التدقيق بالأدلة.")

    files = read_knowledge_files()
    for item in files:
        st.markdown(f"**{item['source']}**")
        st.write(item["text"])
