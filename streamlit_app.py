import sys
from pathlib import Path

# ==========================================
# DYNAMIC PATH RESOLUTION (Fixes ModuleNotFoundError)
# ==========================================
ROOT_DIR = Path(__file__).resolve().parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

# If files like graph.py, config.py are directly in root instead of app/
# also support root module loading or app package layout
PARENT_DIR = ROOT_DIR.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

import json
import time
import requests
import streamlit as st

# ==========================================
# STREAMLIT PAGE CONFIGURATION
# ==========================================
st.set_page_config(
    page_title="DevGuard AI - Security Review",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ==========================================
# CUSTOM STYLING
# ==========================================
st.markdown(
    """
    <style>
    .main-header {
        font-size: 2.2rem;
        font-weight: 700;
        color: #1E293B;
        margin-bottom: 0.2rem;
    }
    .sub-header {
        font-size: 1rem;
        color: #64748B;
        margin-bottom: 1.5rem;
    }
    .badge-critical {
        background-color: #FEE2E2;
        color: #991B1B;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-high {
        background-color: #FFEDD5;
        color: #9A3412;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-medium {
        background-color: #FEF3C7;
        color: #92400E;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    .badge-low {
        background-color: #DCFCE7;
        color: #166534;
        padding: 4px 8px;
        border-radius: 4px;
        font-weight: bold;
    }
    </style>
""",
    unsafe_allow_html=True,
)

# ==========================================
# SAMPLE CODE TEMPLATES
# ==========================================
DEFAULT_VULNERABLE_CODE = """import os
import sqlite3

API_KEY = "sk_live_99887766554433221100"

def get_user_data(user_id):
    # SQL Injection risk
    query = "SELECT * FROM users WHERE id = " + user_id
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)
    
    # Dynamic code execution risk
    user_script = "print('User authenticated')"
    eval(user_script)
    
    return cursor.fetchall()
"""

# ==========================================
# SIDEBAR CONFIGURATION
# ==========================================
with st.sidebar:
    st.title("🛡️ DevGuard AI")

    st.markdown("### ⚙️ Engine Configuration")
    api_url = st.text_input(
        "DevGuard API Base URL",
        value="http://127.0.0.1:8000",
        help="Endpoint where FastAPI server is running.",
    )

    use_direct_workflow = st.checkbox(
        "Run Direct Workflow (Bypass REST API)",
        value=True,
        help="Directly imports DevGuardWorkflow from app.graph if API server is not running.",
    )

    st.markdown("---")
    st.markdown("### 📁 File Input")
    file_path_input = st.text_input("Target File Path", value="main.py")

    st.markdown("---")
    st.caption("DevGuard AI v1.0 | RAG & Deterministic Code Scanner")


# ==========================================
# MAIN INTERFACE
# ==========================================
st.markdown(
    '<div class="main-header">🛡️ DevGuard AI Security Analysis</div>',
    unsafe_allow_html=True,
)
st.markdown(
    '<div class="sub-header">AI-Powered Security Code Review with Hybrid RAG & Static Rule Checking</div>',
    unsafe_allow_html=True,
)

col_left, col_right = st.columns([1, 1], gap="medium")

# --- LEFT COLUMN: Code Input ---
with col_left:
    st.subheader("💻 Source Code Editor")

    uploaded_file = st.file_uploader(
        "Upload a file for review", type=["py", "js", "txt", "md"]
    )

    if uploaded_file is not None:
        file_code = uploaded_file.getvalue().decode("utf-8")
        file_path_input = uploaded_file.name
    else:
        file_code = DEFAULT_VULNERABLE_CODE

    code_input = st.text_area(
        "Edit Python code snippet below:",
        value=file_code,
        height=400,
        help="Paste or edit the code you want DevGuard to analyze.",
    )

    analyze_button = st.button(
        "🚀 Run Security Scan", use_container_width=True, type="primary"
    )

# --- HELPER FUNCTIONS ---
def analyze_via_api(url: str, code: str, file_path: str):
    endpoint = f"{url.rstrip('/')}/analyze"
    payload = {"code": code, "file_path": file_path}
    start_time = time.time()
    response = requests.post(endpoint, json=payload, timeout=120)
    latency = (time.time() - start_time) * 1000
    if response.status_code == 200:
        res_data = response.json()
        if "latency_ms" not in res_data:
            res_data["latency_ms"] = round(latency, 2)
        return res_data
    else:
        raise Exception(
            f"API Error ({response.status_code}): {response.text}"
        )


def analyze_via_direct_import(code: str, file_path: str):
    start_time = time.time()
    try:
        from app.graph import DevGuardWorkflow
    except ModuleNotFoundError:
        from graph import DevGuardWorkflow

    workflow = DevGuardWorkflow()
    result = workflow.invoke(code=code, file_path=file_path)
    latency = (time.time() - start_time) * 1000

    llm_response = result.get("response", "{}")
    parsed_llm = {}
    if isinstance(llm_response, str):
        try:
            cleaned = llm_response.replace("```json", "").replace("```", "").strip()
            parsed_llm = json.loads(cleaned)
        except Exception:
            parsed_llm = {
                "summary": llm_response,
                "overall_score": 50,
                "risk_level": "UNKNOWN",
                "findings": [],
            }
    elif isinstance(llm_response, dict):
        parsed_llm = llm_response

    return {
        "summary": parsed_llm.get("summary", "Analysis completed."),
        "overall_score": parsed_llm.get("overall_score", 100),
        "risk_level": parsed_llm.get("risk_level", "LOW"),
        "findings": parsed_llm.get("findings", result.get("deterministic", [])),
        "deterministic": result.get("deterministic", []),
        "retrieved_policies": [
            p.get("text", "") if isinstance(p, dict) else str(p)
            for p in result.get("policies", [])
        ],
        "latency_ms": round(latency, 2),
    }


# --- RIGHT COLUMN: Analysis Results ---
with col_right:
    st.subheader("📊 Security Analysis Report")

    if analyze_button:
        with st.spinner("Analyzing code against security rules & policies..."):
            try:
                if use_direct_workflow:
                    report = analyze_via_direct_import(code_input, file_path_input)
                else:
                    report = analyze_via_api(api_url, code_input, file_path_input)

                st.session_state["report"] = report
            except Exception as e:
                st.error(f"❌ Analysis failed: {str(e)}")

    if "report" in st.session_state:
        report = st.session_state["report"]

        raw_response = report.get("response", "")
        llm_data = {}
        if isinstance(raw_response, str) and raw_response.strip():
            try:
                cleaned = raw_response.replace("```json", "").replace("```", "").strip()
                llm_data = json.loads(cleaned)
            except Exception:
                llm_data = {"summary": raw_response}

        summary = report.get("summary") or llm_data.get(
            "summary", "Scan complete. Issues identified below."
        )
        score = report.get("overall_score", llm_data.get("overall_score", 70))
        risk_level = str(
            report.get("risk_level", llm_data.get("risk_level", "MEDIUM"))
        ).upper()
        latency = report.get("latency_ms", 0.0)

        # Metrics
        m1, m2, m3 = st.columns(3)
        with m1:
            st.metric(label="Overall Safety Score", value=f"{score}/100")
        with m2:
            st.metric(label="Risk Level", value=risk_level)
        with m3:
            st.metric(label="Scan Latency", value=f"{latency:.0f} ms")

        st.markdown("#### 📝 Executive Summary")
        st.info(summary)

        # Tabs
        tab_scanner, tab_policies, tab_raw = st.tabs(
            ["🔍 Findings", "📜 Retrieved Policies", "🛠️ Raw Output"]
        )

        with tab_scanner:
            findings = (
                report.get("deterministic")
                or report.get("findings")
                or llm_data.get("findings", [])
            )

            if not findings:
                st.success("✅ No security vulnerabilities detected!")
            else:
                for idx, finding in enumerate(findings, start=1):
                    sev = str(finding.get("severity", "medium")).upper()

                    with st.expander(
                        f"#{idx} [{sev}] {finding.get('title', 'Vulnerability Detected')}"
                    ):
                        st.markdown(
                            f"**Category:** `{finding.get('category', 'security')}` | **Line:** `{finding.get('line_number', 'N/A')}`"
                        )
                        st.markdown(
                            f"**Evidence:**\n```python\n{finding.get('evidence', 'N/A')}\n```"
                        )
                        st.markdown(
                            f"**Remediation:**\n{finding.get('remediation', 'N/A')}"
                        )

        with tab_policies:
            policies = report.get(
                "retrieved_policies"
            ) or report.get("policies", [])
            if not policies:
                st.write("No matching policy guidelines retrieved.")
            else:
                for p_idx, pol in enumerate(policies, start=1):
                    pol_text = pol.get("text", str(pol)) if isinstance(pol, dict) else str(pol)
                    pol_source = pol.get("source", "Policy DB") if isinstance(pol, dict) else "Policy DB"
                    with st.expander(f"Policy Reference #{p_idx} ({pol_source})"):
                        st.markdown(pol_text)

        with tab_raw:
            st.json(report)
    else:
        st.info("👈 Edit code on the left and click **Run Security Scan** to generate a report.")