"""Static, hardcoded visual theme (colors inspired by the Saudi Digital
Government visual identity — navy + teal — since no official DGA brand file
was provided) plus automatic per-text-block language direction (Arabic
right-to-left, English/Latin left-to-right).

SECURITY NOTE: this module must NEVER be built from interpolated or
user-influenced content (no f-strings, no request/document data). It is a
single plain string constant injected once via `unsafe_allow_html=True` in
app.py. tests/test_security.py enforces both facts:
  1. `unsafe_allow_html=True` appears in app.py exactly once, rendering only
     this constant.
  2. THEME_CSS itself is a plain string literal (ast.Constant), not an
     f-string/formatted value — i.e. it can never carry attacker-controlled
     content, which is what actually made `unsafe_allow_html` risky before.
Everything that renders document/audit/model output in app.py continues to
use plain st.write()/st.markdown() without unsafe_allow_html, so untrusted
content is always escaped by Streamlit as before.
"""

THEME_CSS = """
<style>
@import url('https://fonts.googleapis.com/css2?family=Tajawal:wght@400;500;700&family=Inter:wght@400;500;600&display=swap');

:root {
    --dga-navy: #0B2545;
    --dga-navy-dark: #071A33;
    --dga-teal: #00A79D;
    --dga-teal-light: #E6F5F4;
    --dga-bg: #F7F9FA;
    --dga-border: #E2E8ED;
}

/* Base RTL app direction (the app's own labels/copy are Arabic-first). */
html, body, [data-testid="stAppViewContainer"], [data-testid="stSidebar"] {
    direction: rtl;
}

* {
    font-family: 'Tajawal', 'Inter', -apple-system, sans-serif;
}

/* Let every text-bearing element auto-detect ITS OWN direction from its
   content, per the Unicode Bidi Algorithm: a block whose text starts with
   Arabic renders right-to-left/right-aligned, a block whose text starts
   with English/Latin renders left-to-right/left-aligned — automatically,
   for every string the app displays (labels, extracted document text,
   model output, file names, etc.) without needing to special-case each one. */
p, span, div, li, td, th, label, h1, h2, h3, h4, h5, h6,
.stMarkdown, .stText, .stAlert, .stException,
textarea, input[type="text"], input[type="password"] {
    unicode-bidi: plaintext;
    text-align: start;
}

/* ---- Header ---- */
[data-testid="stAppViewContainer"] > .main .block-container {
    padding-top: 1.5rem;
}
h1 {
    color: var(--dga-navy);
    border-bottom: 4px solid var(--dga-teal);
    padding-bottom: 0.5rem;
}
h2, h3 {
    color: var(--dga-navy);
}

/* ---- Sidebar ---- */
[data-testid="stSidebar"] {
    background-color: var(--dga-navy);
}
[data-testid="stSidebar"] * {
    color: #FFFFFF !important;
}
[data-testid="stSidebar"] button {
    background-color: var(--dga-teal) !important;
    color: var(--dga-navy-dark) !important;
    border: none !important;
}

/* ---- Buttons ---- */
.stButton > button, .stDownloadButton > button, .stFormSubmitButton > button {
    background-color: var(--dga-teal);
    color: #FFFFFF;
    border: none;
    border-radius: 8px;
    font-weight: 500;
    transition: background-color 0.15s ease-in-out;
}
.stButton > button:hover, .stDownloadButton > button:hover, .stFormSubmitButton > button:hover {
    background-color: var(--dga-navy);
    color: #FFFFFF;
}

/* ---- Inputs / selects / uploader / expander ---- */
.stTextInput input, .stTextArea textarea, .stSelectbox div[data-baseweb="select"] {
    border-radius: 8px !important;
    border: 1px solid var(--dga-border) !important;
}
[data-testid="stFileUploaderDropzone"] {
    background-color: var(--dga-teal-light);
    border: 1.5px dashed var(--dga-teal);
    border-radius: 10px;
}
.streamlit-expanderHeader, [data-testid="stExpander"] summary {
    background-color: var(--dga-teal-light);
    border-radius: 8px;
    color: var(--dga-navy);
    font-weight: 500;
}

/* ---- Misc polish ---- */
[data-testid="stStatusWidget"], .stAlert {
    border-radius: 8px;
}
footer {visibility: hidden;}
</style>
"""
