import hashlib
import streamlit as st
from src.config import (
    OPENAI_API_KEY,
    AUDIT_RATE_LIMIT_MAX,
    AUDIT_RATE_LIMIT_WINDOW_SECONDS,
)
from src.rag.ingest import ensure_vector_store
from src.rag.document_extraction import read_document_text, extract_embedded_images
from src.services.product_pipeline import run_audit
from src.services.standards_catalog import get_frameworks, get_perspectives, get_standards
from src.llm.client import analyze_image_evidence
from src.llm.prompts import build_image_evidence_prompt
from src.security.auth import AUTH_ENABLED, verify_credentials, has_permission, users_file_exists
from src.security.file_validation import validate_document_upload, sanitize_plain_text, MAX_TEXT_LEN
from src.security.rate_limit import check_rate_limit
from src.security.audit_log import log_event, new_correlation_id
from src.ui.theme import THEME_CSS

st.set_page_config(page_title="Digital Transformation Compliance Auditor", layout="wide")
# Static, hardcoded theme only (see src/ui/theme.py docstring for why this is
# the one safe use of unsafe_allow_html in the app — enforced by a test).
st.markdown(THEME_CSS, unsafe_allow_html=True)

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
    "ارفع وثيقة التدقيق (PDF أو Word) وسيقوم النظام تلقائيًا بقراءة نصها، واستخراج أي صور مضمّنة بداخلها "
    "وتحليلها بواسطة نموذج رؤية، ثم قياس مدى الامتثال للمعيار المختار — دون أي خطوات إضافية.")

if not OPENAI_API_KEY:
    st.warning("الرجاء إعداد OPENAI_API_KEY في ملف .env أو كمتغير بيئة لاستخدام نموذج OpenAI.")

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
uploaded_file = st.file_uploader("ارفع الوثيقة (PDF أو Word)", type=["pdf", "docx"])

if uploaded_file is None:
    st.info("ارفع وثيقة PDF أو Word لبدء التدقيق تلقائيًا.")
    st.stop()

if not has_permission(current_role, "run_audit"):
    st.warning("🔒 تشغيل التدقيق التلقائي متاح فقط لدوري Admin وComplianceAuditor.")
    st.stop()

file_bytes = uploaded_file.getvalue()
is_valid, reason = validate_document_upload(file_bytes, uploaded_file.type or "", uploaded_file.name)
if not is_valid:
    st.error(f"تم رفض الملف: {reason}")
    log_event(
        event="file_upload_rejected", correlation_id=correlation_id, user=current_user, role=current_role,
        resource=uploaded_file.name, result="rejected", details=reason,
    )
    st.stop()

if not OPENAI_API_KEY:
    st.error("مفتاح OpenAI مفقود. الرجاء إضافة OPENAI_API_KEY.")
    st.stop()

file_hash = hashlib.sha256(file_bytes).hexdigest()
processing_key = f"{file_hash}:{selected_framework_key}:{selected_standard_id}"

if st.session_state.get("processed_key") != processing_key:
    if not check_rate_limit("audit_run", AUDIT_RATE_LIMIT_MAX, AUDIT_RATE_LIMIT_WINDOW_SECONDS):
        st.error("تم تجاوز الحد المسموح لعدد عمليات التدقيق خلال فترة قصيرة. حاول لاحقًا.")
        log_event(event="rate_limit_exceeded", correlation_id=correlation_id, user=current_user,
                   role=current_role, resource="audit_run", result="blocked")
        st.stop()

    with st.spinner("جارٍ قراءة الوثيقة واستخراج الصور المضمّنة وتحليلها، ثم تشغيل تدقيق الامتثال..."):
        try:
            document_text = sanitize_plain_text(
                read_document_text(uploaded_file, uploaded_file.name), MAX_TEXT_LEN
            )
        except Exception:
            st.error("تعذّرت قراءة الوثيقة. تأكد من أن الملف غير تالف وأعد المحاولة.")
            log_event(
                event="file_processing_error", correlation_id=correlation_id, user=current_user, role=current_role,
                resource=uploaded_file.name, result="error",
            )
            st.stop()

        embedded_images = extract_embedded_images(uploaded_file, uploaded_file.name)
        vision_prompt = build_image_evidence_prompt(selected_standard_id, selected_standard_title)
        image_results = []
        for image in embedded_images:
            try:
                analysis_text = analyze_image_evidence(image["bytes"], image["mime"], vision_prompt)
                log_event(event="image_analysis", correlation_id=correlation_id, user=current_user,
                           role=current_role, resource=image["name"], result="success")
            except Exception:
                analysis_text = "تعذّر تحليل هذه الصورة حاليًا."
                log_event(event="image_analysis", correlation_id=correlation_id, user=current_user,
                           role=current_role, resource=image["name"], result="error")
            image_results.append({"name": image["name"], "analysis": analysis_text})

        ensure_vector_store()

        try:
            result = run_audit(
                document_text,
                user_request="",
                standard_id=selected_standard_id,
                standard_title=selected_standard_title,
                framework_label=selected_framework_label,
                image_evidence_notes=[f"({r['name']}) {r['analysis']}" for r in image_results] or None,
                correlation_id=correlation_id,
                user=current_user,
                role=current_role,
            )
        except Exception:
            st.error("حدث خطأ غير متوقع أثناء التدقيق. تم تسجيل الحادثة داخليًا. حاول مرة أخرى لاحقًا.")
            log_event(event="audit_run", correlation_id=correlation_id, user=current_user,
                       role=current_role, resource=f"standard={selected_standard_id}", result="error")
            st.stop()

        st.session_state["processed_key"] = processing_key
        st.session_state["last_result"] = result
        st.session_state["last_document_text"] = document_text
        st.session_state["last_image_results"] = image_results

result = st.session_state.get("last_result")
if result:
    with st.expander("النص المستخرج من الوثيقة"):
        st.write(st.session_state.get("last_document_text") or "لا يوجد نص قابل للاستخراج.")

    image_results = st.session_state.get("last_image_results") or []
    if image_results:
        st.markdown(f"**تم العثور على {len(image_results)} صورة مضمّنة داخل الوثيقة وتحليلها تلقائيًا:**")
        for item in image_results:
            with st.expander(f"🖼️ {item['name']}"):
                st.write(item["analysis"])

    st.subheader("نتائج التدقيق")
    st.write(result.get("final_answer"))
    if result.get("report_csv") and has_permission(current_role, "download_report"):
        st.download_button(
            label="تنزيل تقرير CSV للامتثال",
            data=result["report_csv"],
            file_name=f"compliance_report_{selected_standard_id}.csv",
            mime="text/csv",
        )
