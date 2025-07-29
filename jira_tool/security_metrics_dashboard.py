#!/usr/bin/env python3
"""
Security Metrics Dashboard for Pentesters and Managers
Standalone dashboard for security-specific KPIs and insights
"""

import streamlit as st
import sys
import os

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from utils.security_metrics import display_security_metrics, SecurityMetrics

# Page configuration
st.set_page_config(
    page_title="Security Metrics Dashboard",
    page_icon="🔒",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for security-focused styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #d62728;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(90deg, #d62728, #ff7f0e);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .security-card {
        background: linear-gradient(135deg, #d62728 0%, #ff7f0e 100%);
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    .risk-high { background-color: #f8d7da; border-left: 4px solid #d62728; }
    .risk-medium { background-color: #fff3cd; border-left: 4px solid #ffc107; }
    .risk-low { background-color: #d4edda; border-left: 4px solid #28a745; }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown('<h1 class="main-header">🔒 Security Metrics Dashboard</h1>', unsafe_allow_html=True)

# Sidebar with security focus
st.sidebar.header("🔒 Security Focus Areas")
st.sidebar.markdown("""
### 🚨 Risk Assessment
- **Critical/High Vulnerabilities** - Immediate attention required
- **Risk Scoring** - Overall security posture
- **Severity Distribution** - Resource prioritization

### ⚡ Exploitability Analysis
- **Highly Exploitable** - ≥80% exploitability
- **Attack Vector Analysis** - Common vulnerability patterns
- **Risk Matrix** - Severity vs Exploitability correlation

### 🔧 Remediation Tracking
- **Ticket Creation Rate** - Process efficiency
- **Remediation Progress** - Open/In Progress/Resolved
- **Dev Ticket Linking** - Development integration

### 📊 Security KPIs
- **Total Vulnerabilities** - Scope of assessment
- **High-Risk Count** - Critical + High severity
- **Exploitability Score** - Average exploitability percentage
- **Remediation Rate** - Progress percentage
""")

st.sidebar.header("📋 Security Metrics")
st.sidebar.markdown("""
- **Risk Score** - Weighted severity scoring
- **Exploitability Distribution** - Attack likelihood
- **Vulnerability Trends** - Common attack vectors
- **Technology Stack Analysis** - Technology-specific risks
- **Remediation Efficiency** - Process effectiveness
""")

# Main content
st.header("📊 Upload Your Security Assessment Data")

# File upload
uploaded_file = st.file_uploader(
    "Choose your unified Excel file with vulnerability data",
    type=["xlsx", "xls"],
    help="Upload your security assessment Excel file to analyze security metrics"
)

if uploaded_file:
    st.success(f"✅ Security data uploaded: {uploaded_file.name}")
    
    # Save uploaded file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        excel_path = tmp_file.name
    
    # Display security metrics
    display_security_metrics(excel_path, "Sheet1")
    
    # Clean up temporary file
    try:
        os.unlink(excel_path)
    except:
        pass

else:
    st.info("🔒 Please upload your security assessment Excel file to begin analysis")
    
    # Show security metrics structure
    st.subheader("🔒 Security Metrics Overview")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🚨 Risk Assessment Metrics
        - **Critical Vulnerabilities** - Immediate action required
        - **High Vulnerabilities** - High priority remediation
        - **Risk Score** - Overall security posture (0-4 scale)
        - **Critical+High Ratio** - Percentage of high-risk findings
        
        ### ⚡ Exploitability Analysis
        - **Highly Exploitable (≥80%)** - Immediate remediation needed
        - **Moderately Exploitable (50-79%)** - Medium priority
        - **Low Exploitable (<50%)** - Lower priority
        - **High-Risk Exploitable** - Critical/High + ≥50% exploitability
        """)
    
    with col2:
        st.markdown("""
        ### 🔧 Remediation Tracking
        - **Ticket Creation Rate** - Process efficiency percentage
        - **Open Vulnerabilities** - Pending remediation
        - **In Progress** - Currently being addressed
        - **Resolved** - Successfully remediated
        - **Dev Ticket Linking** - Development team integration
        
        ### 📊 Security KPIs
        - **Total Vulnerabilities** - Assessment scope
        - **High-Risk Count** - Critical + High severity
        - **Average Exploitability** - Mean exploitability percentage
        - **Remediation Rate** - Progress percentage
        """)
    
    st.subheader("📈 Security Visualizations")
    st.markdown("""
    The dashboard provides security-focused visualizations:
    - **Risk Distribution** - Severity breakdown with color coding
    - **Exploitability vs Severity Matrix** - Risk correlation analysis
    - **Vulnerability Type Trends** - Common attack vectors
    - **Technology Stack Analysis** - Technology-specific risks
    - **Remediation Progress** - Process efficiency tracking
    """)
    
    st.subheader("🎯 Security Recommendations")
    st.markdown("""
    ### Immediate Actions (Critical/High Risk)
    - Prioritize critical vulnerabilities with high exploitability
    - Address highly exploitable findings (≥80%)
    - Focus on high-risk, exploitable combinations
    
    ### Medium-Term Actions
    - Improve remediation rate and ticket creation efficiency
    - Implement technology-specific security training
    - Enhance development team integration
    
    ### Long-Term Strategy
    - Implement secure development practices
    - Automate security testing processes
    - Establish risk-based prioritization frameworks
    """)

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        <p>🔒 Security Metrics Dashboard | Built for Pentesters & Managers</p>
        <p>Focusing on security-specific KPIs, risk assessment, and remediation tracking</p>
    </div>
    """,
    unsafe_allow_html=True
) 