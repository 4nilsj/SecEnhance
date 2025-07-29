#!/usr/bin/env python3
"""
Unified Excel Metrics Module
Provides comprehensive metrics and analysis for the unified Excel sheet
Focuses on the first 15 vulnerability-specific columns
"""

import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import streamlit as st
from datetime import datetime, timedelta
from typing import Dict, List, Tuple, Optional
import re
from collections import Counter, defaultdict

# First 15 columns of the unified Excel sheet (vulnerability-specific)
VULNERABILITY_COLUMNS = [
    "File Name (FullPath)",
    "Vulnerability Name", 
    "Line Number(s)",
    "Severity",
    "Description",
    "Impact",
    "Vulnerable Code Snippet",
    "Potential Fix(Text+Code)",
    "More Info",
    "True Positive (%)",
    "Exploitable(%)",
    "Status",
    "Security Ticket",
    "Security Ticket Status",
    "dev ticket"
]

class UnifiedExcelMetrics:
    """Comprehensive metrics and analysis for unified Excel sheet"""
    
    def __init__(self, excel_file_path: str, sheet_name: str = "Sheet1"):
        self.excel_file_path = excel_file_path
        self.sheet_name = sheet_name
        self.df = None
        self.load_data()
    
    def load_data(self):
        """Load Excel data"""
        try:
            self.df = pd.read_excel(self.excel_file_path, sheet_name=self.sheet_name)
            st.success(f"✅ Loaded {len(self.df)} rows from {self.excel_file_path}")
        except Exception as e:
            st.error(f"❌ Error loading Excel file: {str(e)}")
            self.df = pd.DataFrame()
    
    def get_basic_metrics(self) -> Dict:
        """Get basic metrics for the first 15 columns"""
        if self.df.empty:
            return {}
        
        metrics = {
            "total_rows": len(self.df),
            "total_columns": len(self.df.columns),
            "vulnerability_columns": len(VULNERABILITY_COLUMNS),
            "missing_values": {},
            "data_types": {},
            "unique_values": {},
            "completeness": {}
        }
        
        # Analyze first 15 columns
        for col in VULNERABILITY_COLUMNS:
            if col in self.df.columns:
                metrics["missing_values"][col] = self.df[col].isnull().sum()
                metrics["data_types"][col] = str(self.df[col].dtype)
                metrics["unique_values"][col] = self.df[col].nunique()
                metrics["completeness"][col] = (len(self.df) - self.df[col].isnull().sum()) / len(self.df) * 100
            else:
                metrics["missing_values"][col] = len(self.df)
                metrics["data_types"][col] = "missing"
                metrics["unique_values"][col] = 0
                metrics["completeness"][col] = 0
        
        return metrics
    
    def analyze_severity_distribution(self) -> Dict:
        """Analyze severity distribution"""
        if self.df.empty or "Severity" not in self.df.columns:
            return {}
        
        severity_counts = self.df["Severity"].value_counts()
        severity_percentages = (severity_counts / len(self.df)) * 100
        
        return {
            "counts": severity_counts.to_dict(),
            "percentages": severity_percentages.to_dict(),
            "total": len(self.df),
            "unique_severities": len(severity_counts)
        }
    
    def analyze_true_positive_rates(self) -> Dict:
        """Analyze true positive percentages"""
        if self.df.empty or "True Positive (%)" not in self.df.columns:
            return {}
        
        # Clean and convert to numeric
        tp_col = self.df["True Positive (%)"].astype(str).str.replace('%', '').str.replace(',', '')
        tp_numeric = pd.to_numeric(tp_col, errors='coerce')
        
        return {
            "mean_true_positive": tp_numeric.mean(),
            "median_true_positive": tp_numeric.median(),
            "std_true_positive": tp_numeric.std(),
            "min_true_positive": tp_numeric.min(),
            "max_true_positive": tp_numeric.max(),
            "high_confidence": len(tp_numeric[tp_numeric >= 80]),
            "medium_confidence": len(tp_numeric[(tp_numeric >= 50) & (tp_numeric < 80)]),
            "low_confidence": len(tp_numeric[tp_numeric < 50]),
            "missing_values": tp_numeric.isnull().sum()
        }
    
    def analyze_exploitable_rates(self) -> Dict:
        """Analyze exploitable percentages"""
        if self.df.empty or "Exploitable(%)" not in self.df.columns:
            return {}
        
        # Clean and convert to numeric
        exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
        exp_numeric = pd.to_numeric(exp_col, errors='coerce')
        
        return {
            "mean_exploitable": exp_numeric.mean(),
            "median_exploitable": exp_numeric.median(),
            "std_exploitable": exp_numeric.std(),
            "min_exploitable": exp_numeric.min(),
            "max_exploitable": exp_numeric.max(),
            "high_risk": len(exp_numeric[exp_numeric >= 80]),
            "medium_risk": len(exp_numeric[(exp_numeric >= 50) & (exp_numeric < 80)]),
            "low_risk": len(exp_numeric[exp_numeric < 50]),
            "missing_values": exp_numeric.isnull().sum()
        }
    
    def analyze_vulnerability_types(self) -> Dict:
        """Analyze vulnerability name patterns"""
        if self.df.empty or "Vulnerability Name" not in self.df.columns:
            return {}
        
        vuln_names = self.df["Vulnerability Name"].dropna()
        
        # Extract common patterns
        patterns = {
            "SQL Injection": r"sql.*injection|sqli",
            "XSS": r"xss|cross.*site.*scripting",
            "CSRF": r"csrf|cross.*site.*request.*forgery",
            "Path Traversal": r"path.*traversal|directory.*traversal",
            "Buffer Overflow": r"buffer.*overflow",
            "Authentication": r"auth|authentication|login",
            "Authorization": r"authorization|permission|access.*control",
            "Input Validation": r"input.*validation|validation",
            "Encryption": r"encryption|crypto|cipher",
            "Session": r"session|token"
        }
        
        pattern_counts = {}
        for pattern_name, pattern in patterns.items():
            count = len(vuln_names[vuln_names.str.contains(pattern, case=False, regex=True)])
            pattern_counts[pattern_name] = count
        
        return {
            "total_vulnerabilities": len(vuln_names),
            "unique_vulnerabilities": vuln_names.nunique(),
            "pattern_analysis": pattern_counts,
            "top_vulnerabilities": vuln_names.value_counts().head(10).to_dict()
        }
    
    def analyze_file_extensions(self) -> Dict:
        """Analyze file extensions from File Name (FullPath)"""
        if self.df.empty or "File Name (FullPath)" not in self.df.columns:
            return {}
        
        file_paths = self.df["File Name (FullPath)"].dropna()
        
        # Extract file extensions
        extensions = []
        for path in file_paths:
            if '.' in str(path):
                ext = str(path).split('.')[-1].lower()
                extensions.append(ext)
        
        ext_counts = Counter(extensions)
        
        return {
            "total_files": len(file_paths),
            "unique_extensions": len(ext_counts),
            "extension_distribution": dict(ext_counts.most_common(10)),
            "most_common_extension": ext_counts.most_common(1)[0] if ext_counts else None
        }
    
    def analyze_line_numbers(self) -> Dict:
        """Analyze line number patterns"""
        if self.df.empty or "Line Number(s)" not in self.df.columns:
            return {}
        
        line_numbers = self.df["Line Number(s)"].dropna()
        
        # Extract numeric line numbers
        numeric_lines = []
        for line_str in line_numbers:
            if pd.isna(line_str):
                continue
            # Extract numbers from string
            numbers = re.findall(r'\d+', str(line_str))
            numeric_lines.extend([int(n) for n in numbers])
        
        if numeric_lines:
            return {
                "total_line_references": len(numeric_lines),
                "unique_lines": len(set(numeric_lines)),
                "min_line": min(numeric_lines),
                "max_line": max(numeric_lines),
                "avg_line": np.mean(numeric_lines),
                "median_line": np.median(numeric_lines),
                "line_ranges": {
                    "1-100": len([x for x in numeric_lines if 1 <= x <= 100]),
                    "101-500": len([x for x in numeric_lines if 101 <= x <= 500]),
                    "501-1000": len([x for x in numeric_lines if 501 <= x <= 1000]),
                    "1000+": len([x for x in numeric_lines if x > 1000])
                }
            }
        else:
            return {"total_line_references": 0}
    
    def analyze_status_distribution(self) -> Dict:
        """Analyze status distribution"""
        if self.df.empty or "Status" not in self.df.columns:
            return {}
        
        status_counts = self.df["Status"].value_counts()
        status_percentages = (status_counts / len(self.df)) * 100
        
        return {
            "counts": status_counts.to_dict(),
            "percentages": status_percentages.to_dict(),
            "total": len(self.df),
            "unique_statuses": len(status_counts)
        }
    
    def analyze_security_tickets(self) -> Dict:
        """Analyze security ticket information"""
        if self.df.empty or "Security Ticket" not in self.df.columns:
            return {}
        
        security_tickets = self.df["Security Ticket"].dropna()
        
        # Extract ticket patterns
        ticket_patterns = {
            "has_ticket": len(security_tickets),
            "no_ticket": len(self.df) - len(security_tickets),
            "ticket_completion_rate": (len(security_tickets) / len(self.df)) * 100
        }
        
        # Analyze ticket status if available
        if "Security Ticket Status" in self.df.columns:
            ticket_status = self.df["Security Ticket Status"].dropna()
            status_counts = ticket_status.value_counts()
            ticket_patterns["status_distribution"] = status_counts.to_dict()
        
        return ticket_patterns
    
    def analyze_dev_tickets(self) -> Dict:
        """Analyze dev ticket information"""
        if self.df.empty or "dev ticket" not in self.df.columns:
            return {}
        
        dev_tickets = self.df["dev ticket"].dropna()
        
        return {
            "has_dev_ticket": len(dev_tickets),
            "no_dev_ticket": len(self.df) - len(dev_tickets),
            "dev_ticket_completion_rate": (len(dev_tickets) / len(self.df)) * 100
        }
    
    def get_comprehensive_metrics(self) -> Dict:
        """Get all comprehensive metrics"""
        return {
            "basic_metrics": self.get_basic_metrics(),
            "severity_analysis": self.analyze_severity_distribution(),
            "true_positive_analysis": self.analyze_true_positive_rates(),
            "exploitable_analysis": self.analyze_exploitable_rates(),
            "vulnerability_types": self.analyze_vulnerability_types(),
            "file_extensions": self.analyze_file_extensions(),
            "line_numbers": self.analyze_line_numbers(),
            "status_distribution": self.analyze_status_distribution(),
            "security_tickets": self.analyze_security_tickets(),
            "dev_tickets": self.analyze_dev_tickets()
        }
    
    def create_visualizations(self) -> Dict:
        """Create comprehensive visualizations"""
        charts = {}
        
        # Severity Distribution Chart
        if "Severity" in self.df.columns and not self.df["Severity"].isnull().all():
            severity_counts = self.df["Severity"].value_counts()
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Vulnerability Severity Distribution"
            )
            charts["severity_distribution"] = fig
        
        # True Positive vs Exploitable Scatter Plot
        if "True Positive (%)" in self.df.columns and "Exploitable(%)" in self.df.columns:
            tp_col = self.df["True Positive (%)"].astype(str).str.replace('%', '').str.replace(',', '')
            exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
            tp_numeric = pd.to_numeric(tp_col, errors='coerce')
            exp_numeric = pd.to_numeric(exp_col, errors='coerce')
            
            # Remove NaN values
            valid_data = pd.DataFrame({
                'True_Positive': tp_numeric,
                'Exploitable': exp_numeric
            }).dropna()
            
            if len(valid_data) > 0:
                fig = px.scatter(
                    valid_data,
                    x='True_Positive',
                    y='Exploitable',
                    title="True Positive vs Exploitable Rate",
                    labels={'True_Positive': 'True Positive (%)', 'Exploitable': 'Exploitable (%)'}
                )
                charts["tp_vs_exploitable"] = fig
        
        # File Extension Distribution
        if "File Name (FullPath)" in self.df.columns:
            file_paths = self.df["File Name (FullPath)"].dropna()
            extensions = []
            for path in file_paths:
                if '.' in str(path):
                    ext = str(path).split('.')[-1].lower()
                    extensions.append(ext)
            
            if extensions:
                ext_counts = Counter(extensions)
                fig = px.bar(
                    x=list(ext_counts.keys())[:10],
                    y=list(ext_counts.values())[:10],
                    title="Top 10 File Extensions",
                    labels={'x': 'Extension', 'y': 'Count'}
                )
                charts["file_extensions"] = fig
        
        # Completeness Heatmap
        completeness_data = []
        for col in VULNERABILITY_COLUMNS:
            if col in self.df.columns:
                completeness = (len(self.df) - self.df[col].isnull().sum()) / len(self.df) * 100
                completeness_data.append([col, completeness])
        
        if completeness_data:
            df_completeness = pd.DataFrame(completeness_data, columns=['Column', 'Completeness'])
            fig = px.bar(
                df_completeness,
                x='Column',
                y='Completeness',
                title="Data Completeness by Column",
                labels={'Completeness': 'Completeness (%)'}
            )
            charts["completeness"] = fig
        
        return charts
    
    def generate_metrics_report(self) -> str:
        """Generate a comprehensive metrics report"""
        metrics = self.get_comprehensive_metrics()
        
        report = f"""
# 📊 Unified Excel Metrics Report

## 📋 Basic Information
- **Total Rows:** {metrics['basic_metrics'].get('total_rows', 0)}
- **Total Columns:** {metrics['basic_metrics'].get('total_columns', 0)}
- **Vulnerability Columns:** {metrics['basic_metrics'].get('vulnerability_columns', 0)}

## 🎯 Key Metrics

### Severity Analysis
"""
        
        severity_analysis = metrics.get('severity_analysis', {})
        if severity_analysis:
            report += f"- **Total Vulnerabilities:** {severity_analysis.get('total', 0)}\n"
            report += f"- **Unique Severity Levels:** {severity_analysis.get('unique_severities', 0)}\n"
            for severity, count in severity_analysis.get('counts', {}).items():
                percentage = severity_analysis.get('percentages', {}).get(severity, 0)
                report += f"- **{severity}:** {count} ({percentage:.1f}%)\n"
        
        report += "\n### True Positive Analysis\n"
        tp_analysis = metrics.get('true_positive_analysis', {})
        if tp_analysis:
            report += f"- **Average True Positive Rate:** {tp_analysis.get('mean_true_positive', 0):.1f}%\n"
            report += f"- **High Confidence (≥80%):** {tp_analysis.get('high_confidence', 0)}\n"
            report += f"- **Medium Confidence (50-79%):** {tp_analysis.get('medium_confidence', 0)}\n"
            report += f"- **Low Confidence (<50%):** {tp_analysis.get('low_confidence', 0)}\n"
        
        report += "\n### Exploitable Analysis\n"
        exp_analysis = metrics.get('exploitable_analysis', {})
        if exp_analysis:
            report += f"- **Average Exploitable Rate:** {exp_analysis.get('mean_exploitable', 0):.1f}%\n"
            report += f"- **High Risk (≥80%):** {exp_analysis.get('high_risk', 0)}\n"
            report += f"- **Medium Risk (50-79%):** {exp_analysis.get('medium_risk', 0)}\n"
            report += f"- **Low Risk (<50%):** {exp_analysis.get('low_risk', 0)}\n"
        
        report += "\n### Ticket Analysis\n"
        security_tickets = metrics.get('security_tickets', {})
        if security_tickets:
            report += f"- **Security Tickets Created:** {security_tickets.get('has_ticket', 0)}\n"
            report += f"- **Ticket Completion Rate:** {security_tickets.get('ticket_completion_rate', 0):.1f}%\n"
        
        dev_tickets = metrics.get('dev_tickets', {})
        if dev_tickets:
            report += f"- **Dev Tickets Linked:** {dev_tickets.get('has_dev_ticket', 0)}\n"
            report += f"- **Dev Ticket Completion Rate:** {dev_tickets.get('dev_ticket_completion_rate', 0):.1f}%\n"
        
        return report

def display_unified_excel_metrics(excel_file_path: str, sheet_name: str = "Sheet1"):
    """Display comprehensive metrics for unified Excel sheet"""
    
    st.header("📊 Unified Excel Metrics Dashboard")
    st.subheader("Focusing on First 15 Vulnerability-Specific Columns")
    
    # Initialize metrics
    metrics_analyzer = UnifiedExcelMetrics(excel_file_path, sheet_name)
    
    if metrics_analyzer.df.empty:
        st.error("❌ No data loaded. Please check the Excel file path.")
        return
    
    # Display basic metrics
    st.subheader("📋 Basic Metrics")
    basic_metrics = metrics_analyzer.get_basic_metrics()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Rows", basic_metrics.get('total_rows', 0))
    with col2:
        st.metric("Total Columns", basic_metrics.get('total_columns', 0))
    with col3:
        st.metric("Vulnerability Columns", basic_metrics.get('vulnerability_columns', 0))
    with col4:
        total_missing = sum(basic_metrics.get('missing_values', {}).values())
        st.metric("Total Missing Values", total_missing)
    
    # Display comprehensive metrics
    comprehensive_metrics = metrics_analyzer.get_comprehensive_metrics()
    
    # Create tabs for different metric categories
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🎯 Severity & Risk", 
        "📈 True Positive & Exploitable", 
        "📁 Files & Lines", 
        "🎫 Tickets & Status",
        "📊 Visualizations"
    ])
    
    with tab1:
        st.subheader("🎯 Severity & Risk Analysis")
        
        severity_analysis = comprehensive_metrics.get('severity_analysis', {})
        if severity_analysis:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Severity Distribution:**")
                for severity, count in severity_analysis.get('counts', {}).items():
                    percentage = severity_analysis.get('percentages', {}).get(severity, 0)
                    st.write(f"- {severity}: {count} ({percentage:.1f}%)")
            
            with col2:
                st.write("**Risk Assessment:**")
                st.metric("Total Vulnerabilities", severity_analysis.get('total', 0))
                st.metric("Unique Severity Levels", severity_analysis.get('unique_severities', 0))
    
    with tab2:
        st.subheader("📈 True Positive & Exploitable Analysis")
        
        tp_analysis = comprehensive_metrics.get('true_positive_analysis', {})
        exp_analysis = comprehensive_metrics.get('exploitable_analysis', {})
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**True Positive Analysis:**")
            if tp_analysis:
                st.metric("Average TP Rate", f"{tp_analysis.get('mean_true_positive', 0):.1f}%")
                st.metric("High Confidence", tp_analysis.get('high_confidence', 0))
                st.metric("Medium Confidence", tp_analysis.get('medium_confidence', 0))
                st.metric("Low Confidence", tp_analysis.get('low_confidence', 0))
        
        with col2:
            st.write("**Exploitable Analysis:**")
            if exp_analysis:
                st.metric("Average Exploitable", f"{exp_analysis.get('mean_exploitable', 0):.1f}%")
                st.metric("High Risk", exp_analysis.get('high_risk', 0))
                st.metric("Medium Risk", exp_analysis.get('medium_risk', 0))
                st.metric("Low Risk", exp_analysis.get('low_risk', 0))
    
    with tab3:
        st.subheader("📁 Files & Lines Analysis")
        
        file_analysis = comprehensive_metrics.get('file_extensions', {})
        line_analysis = comprehensive_metrics.get('line_numbers', {})
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**File Analysis:**")
            if file_analysis:
                st.metric("Total Files", file_analysis.get('total_files', 0))
                st.metric("Unique Extensions", file_analysis.get('unique_extensions', 0))
                if file_analysis.get('most_common_extension'):
                    ext, count = file_analysis['most_common_extension']
                    st.metric("Most Common Extension", f"{ext} ({count})")
        
        with col2:
            st.write("**Line Number Analysis:**")
            if line_analysis:
                st.metric("Total Line References", line_analysis.get('total_line_references', 0))
                st.metric("Unique Lines", line_analysis.get('unique_lines', 0))
                if line_analysis.get('avg_line'):
                    st.metric("Average Line", f"{line_analysis['avg_line']:.0f}")
    
    with tab4:
        st.subheader("🎫 Tickets & Status Analysis")
        
        security_tickets = comprehensive_metrics.get('security_tickets', {})
        dev_tickets = comprehensive_metrics.get('dev_tickets', {})
        status_dist = comprehensive_metrics.get('status_distribution', {})
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Security Tickets:**")
            if security_tickets:
                st.metric("Tickets Created", security_tickets.get('has_ticket', 0))
                st.metric("Completion Rate", f"{security_tickets.get('ticket_completion_rate', 0):.1f}%")
        
        with col2:
            st.write("**Dev Tickets:**")
            if dev_tickets:
                st.metric("Dev Tickets Linked", dev_tickets.get('has_dev_ticket', 0))
                st.metric("Dev Completion Rate", f"{dev_tickets.get('dev_ticket_completion_rate', 0):.1f}%")
        
        if status_dist:
            st.write("**Status Distribution:**")
            for status, count in status_dist.get('counts', {}).items():
                percentage = status_dist.get('percentages', {}).get(status, 0)
                st.write(f"- {status}: {count} ({percentage:.1f}%)")
    
    with tab5:
        st.subheader("📊 Visualizations")
        
        charts = metrics_analyzer.create_visualizations()
        
        if "severity_distribution" in charts:
            st.plotly_chart(charts["severity_distribution"], use_container_width=True)
        
        if "tp_vs_exploitable" in charts:
            st.plotly_chart(charts["tp_vs_exploitable"], use_container_width=True)
        
        if "file_extensions" in charts:
            st.plotly_chart(charts["file_extensions"], use_container_width=True)
        
        if "completeness" in charts:
            st.plotly_chart(charts["completeness"], use_container_width=True)
    
    # Display comprehensive report
    with st.expander("📄 Comprehensive Metrics Report"):
        report = metrics_analyzer.generate_metrics_report()
        st.markdown(report)
    
    # Download metrics as JSON
    if st.button("📥 Download Metrics Report"):
        import json
        metrics_json = json.dumps(comprehensive_metrics, indent=2, default=str)
        st.download_button(
            "📥 Download JSON",
            metrics_json,
            file_name=f"unified_excel_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        excel_file = sys.argv[1]
        sheet_name = sys.argv[2] if len(sys.argv) > 2 else "Sheet1"
        display_unified_excel_metrics(excel_file, sheet_name)
    else:
        print("Usage: python excel_metrics.py <excel_file_path> [sheet_name]") 