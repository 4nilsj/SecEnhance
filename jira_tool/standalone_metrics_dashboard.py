#!/usr/bin/env python3
"""
Standalone Unified Excel Metrics Dashboard
Run this script to analyze the first 15 vulnerability-specific columns of your unified Excel file
"""

import streamlit as st
import sys
import os

# Add the parent directory to the path to import core modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.append(parent_dir)

from utils.excel_metrics import display_unified_excel_metrics, UnifiedExcelMetrics

# Page configuration
st.set_page_config(
    page_title="Unified Excel Metrics Dashboard",
    page_icon="📊",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Custom CSS for better styling
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
    .metric-card {
        background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
        color: white;
        padding: 1rem;
        border-radius: 0.5rem;
        text-align: center;
    }
    .info-box {
        background-color: #e3f2fd;
        border: 1px solid #2196f3;
        border-radius: 0.25rem;
        padding: 1rem;
        margin: 1rem 0;
    }
</style>
""", unsafe_allow_html=True)

# Main header
st.markdown('<h1 class="main-header">📊 Unified Excel Metrics Dashboard</h1>', unsafe_allow_html=True)

# Sidebar information
st.sidebar.header("📊 About This Dashboard")
st.sidebar.markdown("""
This dashboard analyzes the first 15 vulnerability-specific columns of your unified Excel file:

1. **File Name (FullPath)**
2. **Vulnerability Name**
3. **Line Number(s)**
4. **Severity**
5. **Description**
6. **Impact**
7. **Vulnerable Code Snippet**
8. **Potential Fix(Text+Code)**
9. **More Info**
10. **True Positive (%)**
11. **Exploitable(%)**
12. **Status**
13. **Security Ticket**
14. **Security Ticket Status**
15. **dev ticket**
""")

st.sidebar.header("📋 Features")
st.sidebar.markdown("""
- **Severity Analysis** - Risk level distribution
- **True Positive vs Exploitable** - Confidence correlation
- **File Extension Analysis** - Technology insights
- **Line Number Patterns** - Code location trends
- **Ticket Completion Rates** - Workflow efficiency
- **Data Completeness** - Quality assessment
- **Vulnerability Type Patterns** - Security focus areas
""")

# Main content
st.header("📊 Upload Your Unified Excel File")

# File upload
uploaded_file = st.file_uploader(
    "Choose your unified Excel file",
    type=["xlsx", "xls"],
    help="Upload your unified Excel file to analyze the first 15 vulnerability-specific columns"
)

if uploaded_file:
    st.success(f"✅ File uploaded: {uploaded_file.name}")
    
    # Save uploaded file
    import tempfile
    with tempfile.NamedTemporaryFile(delete=False, suffix='.xlsx') as tmp_file:
        tmp_file.write(uploaded_file.getvalue())
        excel_path = tmp_file.name
    
    # Display metrics
    display_unified_excel_metrics(excel_path, "Sheet1")
    
    # Clean up temporary file
    try:
        os.unlink(excel_path)
    except:
        pass

else:
    st.info("📊 Please upload your unified Excel file to begin analysis")
    
    # Show example metrics structure
    st.subheader("📋 Example Metrics Structure")
    
    col1, col2 = st.columns(2)
    
    with col1:
        st.markdown("""
        ### 🎯 Severity & Risk Analysis
        - Severity distribution (Critical, High, Medium, Low)
        - Risk assessment metrics
        - Vulnerability type patterns
        
        ### 📈 True Positive & Exploitable
        - Average true positive rates
        - Confidence level analysis
        - Risk correlation analysis
        """)
    
    with col2:
        st.markdown("""
        ### 📁 Files & Lines Analysis
        - File extension distribution
        - Line number patterns
        - Code location trends
        
        ### 🎫 Tickets & Status
        - Security ticket completion rates
        - Dev ticket linking metrics
        - Status distribution analysis
        """)
    
    st.subheader("📊 Sample Visualizations")
    st.markdown("""
    The dashboard will provide:
    - **Pie charts** for severity distribution
    - **Scatter plots** for true positive vs exploitable correlation
    - **Bar charts** for file extensions and completeness
    - **Metrics cards** for key performance indicators
    """)

# Footer
st.markdown("---")
st.markdown(
    """
    <div style='text-align: center; color: #666;'>
        <p>📊 Unified Excel Metrics Dashboard | Built with Streamlit</p>
        <p>Analyzing the first 15 vulnerability-specific columns of your unified Excel file</p>
    </div>
    """,
    unsafe_allow_html=True
) 