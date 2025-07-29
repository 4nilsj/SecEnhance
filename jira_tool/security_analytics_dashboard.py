#!/usr/bin/env python3
"""
Security Analytics Dashboard
Advanced analytics and insights for security professionals
"""

import streamlit as st
import sys
import os

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from utils.security_analytics import display_security_analytics, SecurityAnalytics

# Page configuration
st.set_page_config(
    page_title="Security Analytics Dashboard",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for analytics-focused styling
st.markdown("""
<style>
    .main-header {
        font-size: 2.5rem;
        font-weight: bold;
        color: #1f77b4;
        text-align: center;
        margin-bottom: 2rem;
        background: linear-gradient(90deg, #1f77b4, #ff7f0e);
        -webkit-background-clip: text;
        -webkit-text-fill-color: transparent;
    }
    .analytics-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    .insight-box {
        background-color: #e8f4fd;
        border: 1px solid #2196f3;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
    .prediction-box {
        background-color: #fff3cd;
        border: 1px solid #ffc107;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown('<h1 class="main-header">📊 Security Analytics Dashboard</h1>', unsafe_allow_html=True)

# Sidebar with analytics focus
st.sidebar.header("📊 Analytics Focus Areas")
st.sidebar.markdown("""
### 📈 Trend Analysis
- **Security Trends** - Risk patterns and vulnerability evolution
- **Maturity Assessment** - Security program maturity scoring
- **Risk Distribution** - Severity and exploitability trends
- **Vulnerability Diversity** - Attack vector patterns

### 🎯 Attack Vector Analysis
- **Injection Attacks** - SQL, NoSQL, LDAP, Command injection
- **Cross-Site Scripting** - XSS patterns and prevalence
- **Authentication Issues** - Bypass and weak credential patterns
- **Authorization Problems** - Access control and privilege escalation
- **Path Traversal** - File system access vulnerabilities
- **Security Misconfiguration** - Configuration weaknesses
- **Data Exposure** - Sensitive information disclosure
- **Deserialization** - Object injection vulnerabilities

### 💻 Technology Risk Analysis
- **JavaScript/TypeScript** - Frontend security risks
- **Python** - Backend application security
- **Java** - Enterprise application vulnerabilities
- **PHP** - Web application security
- **C/C++** - System-level security risks
- **C#** - .NET application security
- **Ruby** - Web framework security
- **Go/Rust** - Modern language security

### 🔮 Predictive Insights
- **Remediation Time Prediction** - Based on severity and exploitability
- **Security Posture Improvement** - Current state assessment
- **Focus Area Recommendations** - Priority vulnerability types
- **Trend Predictions** - Future security landscape
""")

st.sidebar.header("📋 Analytics Features")
st.sidebar.markdown("""
- **Security Maturity Scoring** - 100-point maturity assessment
- **Attack Vector Mapping** - Pattern-based vulnerability classification
- **Technology Risk Assessment** - Language/framework-specific analysis
- **Predictive Modeling** - Remediation time and focus predictions
- **Advanced Visualizations** - Radar charts, heatmaps, trend analysis
- **Comprehensive Reporting** - Executive and technical insights
""")

# Main content
st.header("📊 Upload Your Security Data for Advanced Analytics")

# File upload
uploaded_file = st.file_uploader(
    "Choose your unified Excel file with vulnerability data",
    type=["xlsx", "xls"],
    help="Upload your security assessment Excel file for advanced analytics"
)

if uploaded_file:
    st.success(f"✅ Security data uploaded: {uploaded_file.name}")
    
    # Save uploaded file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        excel_path = tmp_file.name
    
    # Display security analytics
    display_security_analytics(excel_path, "Sheet1")
    
    # Clean up temporary file
    try:
        os.unlink(excel_path)
    except:
        pass

else:
    st.info("📊 Please upload your security assessment Excel file to begin advanced analytics")
    
    # Show analytics overview
    st.subheader("📊 Advanced Security Analytics Overview")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 📈 Trend Analysis
        - **Security Maturity Assessment** - 100-point scoring system
        - **Risk Trend Analysis** - Severity and exploitability patterns
        - **Vulnerability Evolution** - Attack vector development trends
        - **Technology Adoption Impact** - Framework-specific risk analysis
        
        ### 🎯 Attack Vector Analytics
        - **Pattern Recognition** - Automated vulnerability classification
        - **Vector Distribution** - Prevalence of attack types
        - **Risk Correlation** - Severity vs exploitability analysis
        - **Technology Mapping** - Language-specific vulnerability patterns
        """)
    
    with col2:
        st.markdown("""
        ### 💻 Technology Risk Analytics
        - **Framework-Specific Risks** - Language and technology analysis
        - **Common Vulnerability Mapping** - Technology-specific patterns
        - **Risk Level Assessment** - Critical/High/Medium/Low classification
        - **Security Control Recommendations** - Technology-specific actions
        
        ### 🔮 Predictive Analytics
        - **Remediation Time Prediction** - ML-based time estimation
        - **Security Posture Forecasting** - Future state predictions
        - **Focus Area Identification** - Priority recommendation engine
        - **Trend Prediction** - Vulnerability evolution forecasting
        """)
    
    st.subheader("📊 Analytics Visualizations")
    st.markdown("""
    The dashboard provides advanced security analytics visualizations:
    
    ### 📈 Security Maturity Radar Chart
    - **Risk Distribution** - Severity-based scoring
    - **Exploitability Analysis** - Attack likelihood assessment
    - **Remediation Progress** - Process efficiency tracking
    - **Process Efficiency** - Workflow optimization metrics
    
    ### 🎯 Attack Vector Distribution
    - **Injection Attacks** - Code injection vulnerability patterns
    - **Cross-Site Scripting** - Client-side security risks
    - **Authentication Issues** - Access control weaknesses
    - **Authorization Problems** - Privilege escalation patterns
    - **Path Traversal** - File system access vulnerabilities
    - **Security Misconfiguration** - Configuration weaknesses
    - **Data Exposure** - Information disclosure risks
    - **Deserialization** - Object injection vulnerabilities
    
    ### 💻 Technology Risk Heatmap
    - **JavaScript/TypeScript** - Frontend security analysis
    - **Python** - Backend application risks
    - **Java** - Enterprise security patterns
    - **PHP** - Web application vulnerabilities
    - **C/C++** - System-level security risks
    - **C#** - .NET application security
    - **Ruby** - Web framework risks
    - **Go/Rust** - Modern language security
    
    ### 📊 Trend Analysis Charts
    - **Severity Distribution** - Risk level breakdown
    - **Exploitability Trends** - Attack likelihood patterns
    - **Vulnerability Evolution** - Type diversity analysis
    - **Technology Adoption** - Framework usage impact
    """)
    
    st.subheader("🔮 Predictive Insights")
    st.markdown("""
    ### 📊 Remediation Time Prediction
    - **High-Risk Items** - Critical/High severity with high exploitability
    - **Medium-Risk Items** - Moderate severity and exploitability
    - **Low-Risk Items** - Lower priority vulnerabilities
    - **Resource Planning** - Team capacity and timeline estimation
    
    ### 🎯 Security Posture Improvement
    - **Current State Assessment** - Maturity level evaluation
    - **Improvement Recommendations** - Actionable next steps
    - **Focus Area Identification** - Priority vulnerability types
    - **Technology-Specific Actions** - Framework-specific recommendations
    
    ### 📈 Trend Predictions
    - **Vulnerability Evolution** - Future attack vector development
    - **Technology Risk Changes** - Framework adoption impact
    - **Security Maturity Progression** - Program development forecasting
    - **Resource Allocation** - Team and tool investment recommendations
    """)
    
    st.subheader("📋 Analytics Report Features")
    st.markdown("""
    ### 📊 Executive Summary
    - **Security Maturity Level** - Advanced/Mature/Developing/Basic
    - **Overall Risk Score** - Weighted severity assessment
    - **Key Risk Indicators** - Critical metrics for management
    - **Trend Analysis** - Risk evolution patterns
    
    ### 🎯 Technical Insights
    - **Attack Vector Analysis** - Vulnerability type distribution
    - **Technology Risk Assessment** - Framework-specific analysis
    - **Remediation Efficiency** - Process optimization metrics
    - **Predictive Modeling** - Future state forecasting
    
    ### 🚀 Actionable Recommendations
    - **Immediate Actions** - Critical security improvements
    - **Technology-Specific Actions** - Framework-focused recommendations
    - **Long-term Strategy** - Security program development
    - **Resource Planning** - Team and tool investment guidance
    """)

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        <p>📊 Security Analytics Dashboard | Advanced Analytics for Security Professionals</p>
        <p>Providing trend analysis, predictive insights, and comprehensive security reporting</p>
    </div>
    """,
    unsafe_allow_html=True
) 