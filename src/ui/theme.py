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

/* Hard-force right-to-left, right-aligned rendering everywhere. Streamlit
   ships its own left-to-right `direction`/`text-align` on internal wrapper
   divs with equal-or-higher specificity, so both properties must be pinned
   with !important on a maximally broad selector, and `text-align: right`
   is used directly (not `start`) so alignment does not depend on how any
   given browser resolves `direction` under unicode-bidi in edge cases. */
*, *::before, *::after {
    direction: rtl !important;
    text-align: right !important;
    font-family: 'Tajawal', 'Inter', -apple-system, sans-serif;
}

/* Inside that RTL frame, let text-bearing content still auto-detect ITS
   OWN reading direction per the Unicode Bidi Algorithm: an English/Latin
   sentence embedded in the (mostly Arabic) extracted document text or
   model output will still shape left-to-right internally, while staying
   inside the right-aligned block above. This does not fight the hard
   right-align rule above — it only affects in-run character ordering. */
p, span, div, li, td, th, label, a,
.stMarkdown, .stMarkdown *, .stText,
[data-testid="stMarkdownContainer"], [data-testid="stMarkdownContainer"] *,
textarea, input[type="text"], input[type="password"] {
    unicode-bidi: plaintext !important;
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

/* ---- Hide Streamlit's default chrome (belt-and-braces on top of
   client.toolbarMode="minimal" in .streamlit/config.toml, in case a given
   Streamlit version still renders part of this markup). ---- */
#MainMenu, header [data-testid="stToolbar"], [data-testid="stDecoration"],
a[href*="deploy" i] {
    visibility: hidden !important;
    height: 0 !important;
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
