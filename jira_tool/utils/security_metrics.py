#!/usr/bin/env python3
"""
Security Metrics Module for Pentesters and Managers
Provides security-specific KPIs and insights for vulnerability management
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

# Security-specific columns from unified Excel
SECURITY_COLUMNS = [
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

class SecurityMetrics:
    """Security-specific metrics for pentesters and managers"""
    
    def __init__(self, excel_file_path: str, sheet_name: str = "Sheet1"):
        self.excel_file_path = excel_file_path
        self.sheet_name = sheet_name
        self.df = None
        self.load_data()
    
    def load_data(self):
        """Load Excel data"""
        try:
            self.df = pd.read_excel(self.excel_file_path, sheet_name=self.sheet_name)
            st.success(f"✅ Loaded {len(self.df)} vulnerabilities from {self.excel_file_path}")
        except Exception as e:
            st.error(f"❌ Error loading Excel file: {str(e)}")
            self.df = pd.DataFrame()
    
    def calculate_security_kpis(self) -> Dict:
        """Calculate key security KPIs for management"""
        if self.df.empty:
            return {}
        
        # Basic counts
        total_vulns = len(self.df)
        critical_vulns = len(self.df[self.df["Severity"].str.contains("Critical", case=False, na=False)])
        high_vulns = len(self.df[self.df["Severity"].str.contains("High", case=False, na=False)])
        medium_vulns = len(self.df[self.df["Severity"].str.contains("Medium", case=False, na=False)])
        low_vulns = len(self.df[self.df["Severity"].str.contains("Low", case=False, na=False)])
        
        # Risk metrics
        high_risk_vulns = critical_vulns + high_vulns
        risk_score = (critical_vulns * 4 + high_vulns * 3 + medium_vulns * 2 + low_vulns * 1) / total_vulns if total_vulns > 0 else 0
        
        # Exploitable analysis
        if "Exploitable(%)" in self.df.columns:
            exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
            exp_numeric = pd.to_numeric(exp_col, errors='coerce')
            highly_exploitable = len(exp_numeric[exp_numeric >= 80])
            moderately_exploitable = len(exp_numeric[(exp_numeric >= 50) & (exp_numeric < 80)])
            avg_exploitability = exp_numeric.mean()
        else:
            highly_exploitable = moderately_exploitable = avg_exploitability = 0
        
        # True positive analysis
        if "True Positive (%)" in self.df.columns:
            tp_col = self.df["True Positive (%)"].astype(str).str.replace('%', '').str.replace(',', '')
            tp_numeric = pd.to_numeric(tp_col, errors='coerce')
            high_confidence = len(tp_numeric[tp_numeric >= 80])
            avg_confidence = tp_numeric.mean()
        else:
            high_confidence = avg_confidence = 0
        
        # Remediation tracking
        tickets_created = len(self.df[self.df["Security Ticket"].notna()])
        remediation_rate = (tickets_created / total_vulns) * 100 if total_vulns > 0 else 0
        
        # Status analysis
        if "Status" in self.df.columns:
            open_vulns = len(self.df[self.df["Status"].str.contains("Open|New|Active", case=False, na=False)])
            in_progress = len(self.df[self.df["Status"].str.contains("In Progress|Working", case=False, na=False)])
            resolved = len(self.df[self.df["Status"].str.contains("Resolved|Fixed|Closed", case=False, na=False)])
        else:
            open_vulns = in_progress = resolved = 0
        
        return {
            "total_vulnerabilities": total_vulns,
            "critical_vulnerabilities": critical_vulns,
            "high_vulnerabilities": high_vulns,
            "medium_vulnerabilities": medium_vulns,
            "low_vulnerabilities": low_vulns,
            "high_risk_vulnerabilities": high_risk_vulns,
            "risk_score": risk_score,
            "highly_exploitable": highly_exploitable,
            "moderately_exploitable": moderately_exploitable,
            "avg_exploitability": avg_exploitability,
            "high_confidence_findings": high_confidence,
            "avg_confidence": avg_confidence,
            "tickets_created": tickets_created,
            "remediation_rate": remediation_rate,
            "open_vulnerabilities": open_vulns,
            "in_progress_vulnerabilities": in_progress,
            "resolved_vulnerabilities": resolved
        }
    
    def analyze_vulnerability_trends(self) -> Dict:
        """Analyze vulnerability patterns and trends"""
        if self.df.empty or "Vulnerability Name" not in self.df.columns:
            return {}
        
        vuln_names = self.df["Vulnerability Name"].dropna()
        
        # Common vulnerability patterns
        vuln_patterns = {
            "SQL Injection": r"sql.*injection|sqli|sql.*inject",
            "Cross-Site Scripting (XSS)": r"xss|cross.*site.*scripting|script.*injection",
            "Cross-Site Request Forgery (CSRF)": r"csrf|cross.*site.*request.*forgery",
            "Path Traversal": r"path.*traversal|directory.*traversal|../|\.\./",
            "Buffer Overflow": r"buffer.*overflow|stack.*overflow|heap.*overflow",
            "Authentication Bypass": r"auth.*bypass|authentication.*bypass|login.*bypass",
            "Authorization Issues": r"authorization|permission|access.*control|privilege.*escalation",
            "Input Validation": r"input.*validation|validation|sanitization",
            "Insecure Deserialization": r"deserialization|unserialize|pickle",
            "Security Misconfiguration": r"misconfiguration|configuration|default.*password",
            "Sensitive Data Exposure": r"exposure|sensitive.*data|password.*exposure|token.*exposure",
            "Broken Access Control": r"access.*control|authorization|permission",
            "XML External Entity (XXE)": r"xxe|xml.*external.*entity",
            "Insecure Direct Object References": r"idor|direct.*object.*reference",
            "Security Logging": r"logging|audit|log.*injection"
        }
        
        pattern_counts = {}
        for pattern_name, pattern in vuln_patterns.items():
            count = len(vuln_names[vuln_names.str.contains(pattern, case=False, regex=True)])
            if count > 0:
                pattern_counts[pattern_name] = count
        
        # Top vulnerability types
        top_vulns = vuln_names.value_counts().head(10).to_dict()
        
        return {
            "vulnerability_patterns": pattern_counts,
            "top_vulnerability_types": top_vulns,
            "unique_vulnerability_types": vuln_names.nunique(),
            "most_common_vulnerability": vuln_names.mode().iloc[0] if not vuln_names.empty else None
        }
    
    def analyze_risk_distribution(self) -> Dict:
        """Analyze risk distribution and severity patterns"""
        if self.df.empty or "Severity" not in self.df.columns:
            return {}
        
        severity_counts = self.df["Severity"].value_counts()
        severity_percentages = (severity_counts / len(self.df)) * 100
        
        # Risk scoring
        risk_scores = {
            "Critical": 4,
            "High": 3,
            "Medium": 2,
            "Low": 1,
            "Info": 0
        }
        
        total_risk_score = 0
        for severity, count in severity_counts.items():
            score = risk_scores.get(severity, 0)
            total_risk_score += score * count
        
        avg_risk_score = total_risk_score / len(self.df) if len(self.df) > 0 else 0
        
        return {
            "severity_distribution": severity_counts.to_dict(),
            "severity_percentages": severity_percentages.to_dict(),
            "total_risk_score": total_risk_score,
            "average_risk_score": avg_risk_score,
            "critical_high_ratio": (severity_counts.get("Critical", 0) + severity_counts.get("High", 0)) / len(self.df) * 100 if len(self.df) > 0 else 0
        }
    
    def analyze_exploitability_metrics(self) -> Dict:
        """Analyze exploitability and attack vectors"""
        if self.df.empty or "Exploitable(%)" not in self.df.columns:
            return {}
        
        exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
        exp_numeric = pd.to_numeric(exp_col, errors='coerce')
        
        # Exploitability categories
        highly_exploitable = exp_numeric[exp_numeric >= 80]
        moderately_exploitable = exp_numeric[(exp_numeric >= 50) & (exp_numeric < 80)]
        low_exploitable = exp_numeric[exp_numeric < 50]
        
        # Combine with severity for risk assessment
        if "Severity" in self.df.columns:
            high_risk_exploitable = len(self.df[
                (self.df["Severity"].str.contains("Critical|High", case=False, na=False)) & 
                (exp_numeric >= 50)
            ])
        else:
            high_risk_exploitable = 0
        
        return {
            "highly_exploitable_count": len(highly_exploitable),
            "moderately_exploitable_count": len(moderately_exploitable),
            "low_exploitable_count": len(low_exploitable),
            "highly_exploitable_percentage": len(highly_exploitable) / len(exp_numeric) * 100 if len(exp_numeric) > 0 else 0,
            "avg_exploitability": exp_numeric.mean(),
            "max_exploitability": exp_numeric.max(),
            "min_exploitability": exp_numeric.min(),
            "high_risk_exploitable": high_risk_exploitable,
            "exploitability_distribution": {
                "80-100%": len(highly_exploitable),
                "50-79%": len(moderately_exploitable),
                "0-49%": len(low_exploitable)
            }
        }
    
    def analyze_remediation_metrics(self) -> Dict:
        """Analyze remediation progress and efficiency"""
        if self.df.empty:
            return {}
        
        # Ticket creation metrics
        tickets_created = len(self.df[self.df["Security Ticket"].notna()])
        tickets_pending = len(self.df) - tickets_created
        
        # Status-based remediation
        if "Status" in self.df.columns:
            status_counts = self.df["Status"].value_counts()
            
            # Categorize statuses
            open_statuses = ["Open", "New", "Active", "Pending"]
            in_progress_statuses = ["In Progress", "Working", "Under Review", "Testing"]
            resolved_statuses = ["Resolved", "Fixed", "Closed", "Completed", "Done"]
            
            open_count = sum(status_counts.get(status, 0) for status in open_statuses if status in status_counts.index)
            in_progress_count = sum(status_counts.get(status, 0) for status in in_progress_statuses if status in status_counts.index)
            resolved_count = sum(status_counts.get(status, 0) for status in resolved_statuses if status in status_counts.index)
        else:
            open_count = in_progress_count = resolved_count = 0
        
        # Dev ticket linking
        if "dev ticket" in self.df.columns:
            dev_tickets_linked = len(self.df[self.df["dev ticket"].notna()])
            dev_linking_rate = (dev_tickets_linked / len(self.df)) * 100 if len(self.df) > 0 else 0
        else:
            dev_tickets_linked = dev_linking_rate = 0
        
        return {
            "total_vulnerabilities": len(self.df),
            "tickets_created": tickets_created,
            "tickets_pending": tickets_pending,
            "ticket_creation_rate": (tickets_created / len(self.df)) * 100 if len(self.df) > 0 else 0,
            "open_vulnerabilities": open_count,
            "in_progress_vulnerabilities": in_progress_count,
            "resolved_vulnerabilities": resolved_count,
            "remediation_rate": (resolved_count / len(self.df)) * 100 if len(self.df) > 0 else 0,
            "dev_tickets_linked": dev_tickets_linked,
            "dev_linking_rate": dev_linking_rate,
            "avg_time_to_ticket": "N/A",  # Would need timestamp data
            "avg_time_to_resolution": "N/A"  # Would need timestamp data
        }
    
    def analyze_technology_stack(self) -> Dict:
        """Analyze technology stack and file types"""
        if self.df.empty or "File Name (FullPath)" not in self.df.columns:
            return {}
        
        file_paths = self.df["File Name (FullPath)"].dropna()
        
        # Extract file extensions and technologies
        extensions = []
        technologies = []
        
        for path in file_paths:
            if '.' in str(path):
                ext = str(path).split('.')[-1].lower()
                extensions.append(ext)
                
                # Map extensions to technologies
                tech_mapping = {
                    'js': 'JavaScript', 'ts': 'TypeScript', 'jsx': 'React', 'tsx': 'React TypeScript',
                    'py': 'Python', 'java': 'Java', 'cs': 'C#', 'cpp': 'C++', 'c': 'C',
                    'php': 'PHP', 'rb': 'Ruby', 'go': 'Go', 'rs': 'Rust',
                    'html': 'HTML', 'css': 'CSS', 'xml': 'XML', 'json': 'JSON',
                    'sql': 'SQL', 'sh': 'Shell', 'ps1': 'PowerShell',
                    'dockerfile': 'Docker', 'yml': 'YAML', 'yaml': 'YAML',
                    'md': 'Markdown', 'txt': 'Text'
                }
                
                if ext in tech_mapping:
                    technologies.append(tech_mapping[ext])
        
        ext_counts = Counter(extensions)
        tech_counts = Counter(technologies)
        
        return {
            "total_files": len(file_paths),
            "unique_extensions": len(ext_counts),
            "unique_technologies": len(tech_counts),
            "top_extensions": dict(ext_counts.most_common(10)),
            "top_technologies": dict(tech_counts.most_common(10)),
            "most_common_technology": tech_counts.most_common(1)[0] if tech_counts else None,
            "technology_distribution": dict(tech_counts)
        }
    
    def generate_security_report(self) -> str:
        """Generate comprehensive security report for management"""
        kpis = self.calculate_security_kpis()
        risk_analysis = self.analyze_risk_distribution()
        exploitability = self.analyze_exploitability_metrics()
        remediation = self.analyze_remediation_metrics()
        vuln_trends = self.analyze_vulnerability_trends()
        tech_stack = self.analyze_technology_stack()
        
        report = f"""
# 🔒 Security Assessment Report

## 📊 Executive Summary
- **Total Vulnerabilities Found:** {kpis.get('total_vulnerabilities', 0)}
- **High-Risk Vulnerabilities:** {kpis.get('high_risk_vulnerabilities', 0)} (Critical + High)
- **Overall Risk Score:** {kpis.get('risk_score', 0):.2f}/4.0
- **Remediation Rate:** {kpis.get('remediation_rate', 0):.1f}%

## 🎯 Critical Security Metrics

### Risk Assessment
- **Critical Vulnerabilities:** {kpis.get('critical_vulnerabilities', 0)}
- **High Vulnerabilities:** {kpis.get('high_vulnerabilities', 0)}
- **Medium Vulnerabilities:** {kpis.get('medium_vulnerabilities', 0)}
- **Low Vulnerabilities:** {kpis.get('low_vulnerabilities', 0)}

### Exploitability Analysis
- **Highly Exploitable (≥80%):** {kpis.get('highly_exploitable', 0)}
- **Moderately Exploitable (50-79%):** {kpis.get('moderately_exploitable', 0)}
- **Average Exploitability:** {kpis.get('avg_exploitability', 0):.1f}%

### Remediation Progress
- **Tickets Created:** {kpis.get('tickets_created', 0)}
- **Open Vulnerabilities:** {kpis.get('open_vulnerabilities', 0)}
- **In Progress:** {kpis.get('in_progress_vulnerabilities', 0)}
- **Resolved:** {kpis.get('resolved_vulnerabilities', 0)}

## 🚨 High-Priority Findings

### Most Common Vulnerability Types
"""
        
        if vuln_trends.get('top_vulnerability_types'):
            for vuln_type, count in list(vuln_trends['top_vulnerability_types'].items())[:5]:
                report += f"- **{vuln_type}:** {count} instances\n"
        
        report += f"""
### Technology Stack Analysis
- **Most Common Technology:** {tech_stack.get('most_common_technology', 'N/A')}
- **Unique Technologies:** {tech_stack.get('unique_technologies', 0)}
- **Files Analyzed:** {tech_stack.get('total_files', 0)}

## 📈 Recommendations

### Immediate Actions (Critical/High Risk)
1. **Prioritize Critical Vulnerabilities:** {kpis.get('critical_vulnerabilities', 0)} critical findings require immediate attention
2. **Address Highly Exploitable Issues:** {kpis.get('highly_exploitable', 0)} vulnerabilities with ≥80% exploitability
3. **Focus on High-Risk Exploitable:** {exploitability.get('high_risk_exploitable', 0)} high-severity, exploitable vulnerabilities

### Medium-Term Actions
1. **Improve Remediation Rate:** Current rate is {kpis.get('remediation_rate', 0):.1f}%, target 90%+
2. **Enhance Ticket Creation:** {kpis.get('tickets_pending', 0)} vulnerabilities still need tickets
3. **Technology-Specific Training:** Focus on {tech_stack.get('most_common_technology', 'N/A')} vulnerabilities

### Long-Term Strategy
1. **Implement Secure Development:** Address {vuln_trends.get('unique_vulnerability_types', 0)} unique vulnerability types
2. **Automated Security Testing:** Reduce manual effort for {tech_stack.get('total_files', 0)} files
3. **Risk-Based Prioritization:** Use exploitability scores for better resource allocation

## 📊 Risk Matrix Summary
- **Critical + High Risk:** {kpis.get('high_risk_vulnerabilities', 0)} vulnerabilities
- **High Exploitability:** {kpis.get('highly_exploitable', 0)} vulnerabilities
- **High Confidence:** {kpis.get('high_confidence_findings', 0)} findings
- **Overall Risk Level:** {'HIGH' if kpis.get('risk_score', 0) > 3 else 'MEDIUM' if kpis.get('risk_score', 0) > 2 else 'LOW'}
"""
        
        return report
    
    def create_security_visualizations(self) -> Dict:
        """Create security-specific visualizations"""
        charts = {}
        
        # Risk Distribution Pie Chart
        if "Severity" in self.df.columns and not self.df["Severity"].isnull().all():
            severity_counts = self.df["Severity"].value_counts()
            fig = px.pie(
                values=severity_counts.values,
                names=severity_counts.index,
                title="Vulnerability Severity Distribution",
                color_discrete_map={
                    "Critical": "#d62728",
                    "High": "#ff7f0e", 
                    "Medium": "#ffec8b",
                    "Low": "#2ca02c"
                }
            )
            charts["risk_distribution"] = fig
        
        # Exploitability vs Severity Scatter Plot
        if "Exploitable(%)" in self.df.columns and "Severity" in self.df.columns:
            exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
            exp_numeric = pd.to_numeric(exp_col, errors='coerce')
            
            # Create severity numeric mapping
            severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            severity_numeric = self.df["Severity"].map(severity_map)
            
            # Combine data
            plot_data = pd.DataFrame({
                'Exploitability': exp_numeric,
                'Severity': severity_numeric,
                'Severity_Label': self.df["Severity"]
            }).dropna()
            
            if len(plot_data) > 0:
                fig = px.scatter(
                    plot_data,
                    x='Exploitability',
                    y='Severity',
                    color='Severity_Label',
                    title="Exploitability vs Severity Risk Matrix",
                    labels={'Exploitability': 'Exploitability (%)', 'Severity': 'Severity Level'}
                )
                charts["exploitability_vs_severity"] = fig
        
        # Vulnerability Type Distribution
        if "Vulnerability Name" in self.df.columns:
            vuln_counts = self.df["Vulnerability Name"].value_counts().head(10)
            fig = px.bar(
                x=vuln_counts.index,
                y=vuln_counts.values,
                title="Top 10 Vulnerability Types",
                labels={'x': 'Vulnerability Type', 'y': 'Count'}
            )
            charts["vulnerability_types"] = fig
        
        # Technology Stack Analysis
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
                    title="Technology Stack by File Extensions",
                    labels={'x': 'File Extension', 'y': 'Count'}
                )
                charts["technology_stack"] = fig
        
        # Remediation Progress
        kpis = self.calculate_security_kpis()
        if kpis:
            progress_data = {
                'Status': ['Open', 'In Progress', 'Resolved'],
                'Count': [
                    kpis.get('open_vulnerabilities', 0),
                    kpis.get('in_progress_vulnerabilities', 0),
                    kpis.get('resolved_vulnerabilities', 0)
                ]
            }
            df_progress = pd.DataFrame(progress_data)
            
            fig = px.pie(
                df_progress,
                values='Count',
                names='Status',
                title="Remediation Progress",
                color_discrete_map={
                    "Open": "#d62728",
                    "In Progress": "#ff7f0e",
                    "Resolved": "#2ca02c"
                }
            )
            charts["remediation_progress"] = fig
        
        return charts

def display_security_metrics(excel_file_path: str, sheet_name: str = "Sheet1"):
    """Display comprehensive security metrics for pentesters and managers"""
    
    st.header("🔒 Security Metrics Dashboard")
    st.subheader("Pentester & Manager Focused Analysis")
    
    # Initialize security metrics
    security_analyzer = SecurityMetrics(excel_file_path, sheet_name)
    
    if security_analyzer.df.empty:
        st.error("❌ No data loaded. Please check the Excel file path.")
        return
    
    # Display security KPIs
    st.subheader("📊 Security KPIs")
    kpis = security_analyzer.calculate_security_kpis()
    
    # Create metric cards
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Vulnerabilities", kpis.get('total_vulnerabilities', 0))
        st.metric("High-Risk Vulns", kpis.get('high_risk_vulnerabilities', 0))
    with col2:
        st.metric("Critical Vulns", kpis.get('critical_vulnerabilities', 0))
        st.metric("Highly Exploitable", kpis.get('highly_exploitable', 0))
    with col3:
        st.metric("Risk Score", f"{kpis.get('risk_score', 0):.2f}/4.0")
        st.metric("Avg Exploitability", f"{kpis.get('avg_exploitability', 0):.1f}%")
    with col4:
        st.metric("Remediation Rate", f"{kpis.get('remediation_rate', 0):.1f}%")
        st.metric("Tickets Created", kpis.get('tickets_created', 0))
    
    # Create tabs for different security analyses
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "🚨 Risk Assessment", 
        "⚡ Exploitability Analysis", 
        "🔧 Remediation Tracking", 
        "📊 Vulnerability Trends",
        "📈 Security Visualizations"
    ])
    
    with tab1:
        st.subheader("🚨 Risk Assessment")
        
        risk_analysis = security_analyzer.analyze_risk_distribution()
        if risk_analysis:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Severity Distribution:**")
                for severity, count in risk_analysis.get('severity_distribution', {}).items():
                    percentage = risk_analysis.get('severity_percentages', {}).get(severity, 0)
                    st.write(f"- {severity}: {count} ({percentage:.1f}%)")
            
            with col2:
                st.write("**Risk Metrics:**")
                st.metric("Total Risk Score", f"{risk_analysis.get('total_risk_score', 0):.0f}")
                st.metric("Average Risk Score", f"{risk_analysis.get('average_risk_score', 0):.2f}")
                st.metric("Critical+High Ratio", f"{risk_analysis.get('critical_high_ratio', 0):.1f}%")
    
    with tab2:
        st.subheader("⚡ Exploitability Analysis")
        
        exploitability = security_analyzer.analyze_exploitability_metrics()
        if exploitability:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Exploitability Distribution:**")
                for range_name, count in exploitability.get('exploitability_distribution', {}).items():
                    st.write(f"- {range_name}: {count}")
            
            with col2:
                st.write("**Key Metrics:**")
                st.metric("Highly Exploitable", exploitability.get('highly_exploitable_count', 0))
                st.metric("High-Risk Exploitable", exploitability.get('high_risk_exploitable', 0))
                st.metric("Average Exploitability", f"{exploitability.get('avg_exploitability', 0):.1f}%")
    
    with tab3:
        st.subheader("🔧 Remediation Tracking")
        
        remediation = security_analyzer.analyze_remediation_metrics()
        if remediation:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Ticket Management:**")
                st.metric("Tickets Created", remediation.get('tickets_created', 0))
                st.metric("Creation Rate", f"{remediation.get('ticket_creation_rate', 0):.1f}%")
                st.metric("Dev Tickets Linked", remediation.get('dev_tickets_linked', 0))
            
            with col2:
                st.write("**Progress Tracking:**")
                st.metric("Open Vulns", remediation.get('open_vulnerabilities', 0))
                st.metric("In Progress", remediation.get('in_progress_vulnerabilities', 0))
                st.metric("Resolved", remediation.get('resolved_vulnerabilities', 0))
                st.metric("Remediation Rate", f"{remediation.get('remediation_rate', 0):.1f}%")
    
    with tab4:
        st.subheader("📊 Vulnerability Trends")
        
        vuln_trends = security_analyzer.analyze_vulnerability_trends()
        tech_stack = security_analyzer.analyze_technology_stack()
        
        col1, col2 = st.columns(2)
        with col1:
            st.write("**Top Vulnerability Types:**")
            if vuln_trends.get('top_vulnerability_types'):
                for vuln_type, count in list(vuln_trends['top_vulnerability_types'].items())[:5]:
                    st.write(f"- {vuln_type}: {count}")
        
        with col2:
            st.write("**Technology Stack:**")
            if tech_stack.get('top_technologies'):
                for tech, count in list(tech_stack['top_technologies'].items())[:5]:
                    st.write(f"- {tech}: {count}")
    
    with tab5:
        st.subheader("📈 Security Visualizations")
        
        charts = security_analyzer.create_security_visualizations()
        
        if "risk_distribution" in charts:
            st.plotly_chart(charts["risk_distribution"], use_container_width=True)
        
        if "exploitability_vs_severity" in charts:
            st.plotly_chart(charts["exploitability_vs_severity"], use_container_width=True)
        
        if "vulnerability_types" in charts:
            st.plotly_chart(charts["vulnerability_types"], use_container_width=True)
        
        if "technology_stack" in charts:
            st.plotly_chart(charts["technology_stack"], use_container_width=True)
        
        if "remediation_progress" in charts:
            st.plotly_chart(charts["remediation_progress"], use_container_width=True)
    
    # Display comprehensive security report
    with st.expander("📄 Security Assessment Report"):
        report = security_analyzer.generate_security_report()
        st.markdown(report)
    
    # Download security metrics as JSON
    if st.button("📥 Download Security Report"):
        import json
        comprehensive_metrics = {
            "kpis": kpis,
            "risk_analysis": security_analyzer.analyze_risk_distribution(),
            "exploitability": security_analyzer.analyze_exploitability_metrics(),
            "remediation": security_analyzer.analyze_remediation_metrics(),
            "vulnerability_trends": security_analyzer.analyze_vulnerability_trends(),
            "technology_stack": security_analyzer.analyze_technology_stack()
        }
        metrics_json = json.dumps(comprehensive_metrics, indent=2, default=str)
        st.download_button(
            "📥 Download Security Report JSON",
            metrics_json,
            file_name=f"security_metrics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        excel_file = sys.argv[1]
        sheet_name = sys.argv[2] if len(sys.argv) > 2 else "Sheet1"
        display_security_metrics(excel_file, sheet_name)
    else:
        print("Usage: python security_metrics.py <excel_file_path> [sheet_name]") 