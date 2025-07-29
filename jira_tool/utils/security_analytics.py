#!/usr/bin/env python3
"""
Security Analytics Module
Advanced analytics and insights for security metrics
Provides trend analysis, predictive insights, and detailed reporting
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
from sklearn.linear_model import LinearRegression
from sklearn.preprocessing import StandardScaler
import warnings
warnings.filterwarnings('ignore')

class SecurityAnalytics:
    """Advanced security analytics and insights"""
    
    def __init__(self, excel_file_path: str, sheet_name: str = "Sheet1"):
        self.excel_file_path = excel_file_path
        self.sheet_name = sheet_name
        self.df = None
        self.load_data()
    
    def load_data(self):
        """Load Excel data"""
        try:
            self.df = pd.read_excel(self.excel_file_path, sheet_name=self.sheet_name)
            st.success(f"✅ Loaded {len(self.df)} vulnerabilities for analytics")
        except Exception as e:
            st.error(f"❌ Error loading Excel file: {str(e)}")
            self.df = pd.DataFrame()
    
    def analyze_security_trends(self) -> Dict:
        """Analyze security trends and patterns"""
        if self.df.empty:
            return {}
        
        trends = {}
        
        # Severity trend analysis
        if "Severity" in self.df.columns:
            severity_counts = self.df["Severity"].value_counts()
            trends["severity_distribution"] = severity_counts.to_dict()
            
            # Risk trend calculation
            risk_scores = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            self.df["risk_score"] = self.df["Severity"].map(risk_scores)
            trends["avg_risk_score"] = self.df["risk_score"].mean()
            trends["risk_trend"] = "Increasing" if self.df["risk_score"].mean() > 2.5 else "Stable" if self.df["risk_score"].mean() > 1.5 else "Decreasing"
        
        # Exploitability trend analysis
        if "Exploitable(%)" in self.df.columns:
            exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
            exp_numeric = pd.to_numeric(exp_col, errors='coerce')
            
            trends["avg_exploitability"] = exp_numeric.mean()
            trends["highly_exploitable_pct"] = (len(exp_numeric[exp_numeric >= 80]) / len(exp_numeric)) * 100 if len(exp_numeric) > 0 else 0
            trends["exploitability_trend"] = "High Risk" if exp_numeric.mean() > 70 else "Medium Risk" if exp_numeric.mean() > 40 else "Low Risk"
        
        # Vulnerability type trends
        if "Vulnerability Name" in self.df.columns:
            vuln_counts = self.df["Vulnerability Name"].value_counts()
            trends["top_vulnerability_types"] = vuln_counts.head(5).to_dict()
            trends["unique_vulnerability_count"] = len(vuln_counts)
            trends["vulnerability_diversity"] = "High" if len(vuln_counts) > 10 else "Medium" if len(vuln_counts) > 5 else "Low"
        
        return trends
    
    def calculate_security_maturity_score(self) -> Dict:
        """Calculate security maturity score based on various factors"""
        if self.df.empty:
            return {}
        
        maturity_score = 0
        max_score = 100
        factors = {}
        
        # Factor 1: Risk Distribution (25 points)
        if "Severity" in self.df.columns:
            critical_pct = (len(self.df[self.df["Severity"].str.contains("Critical", case=False, na=False)]) / len(self.df)) * 100
            high_pct = (len(self.df[self.df["Severity"].str.contains("High", case=False, na=False)]) / len(self.df)) * 100
            
            risk_score = 25 - (critical_pct * 0.5) - (high_pct * 0.25)
            factors["risk_distribution"] = max(0, risk_score)
            maturity_score += factors["risk_distribution"]
        
        # Factor 2: Exploitability (25 points)
        if "Exploitable(%)" in self.df.columns:
            exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
            exp_numeric = pd.to_numeric(exp_col, errors='coerce')
            avg_exploitability = exp_numeric.mean()
            
            exploitability_score = 25 - (avg_exploitability * 0.25)
            factors["exploitability"] = max(0, exploitability_score)
            maturity_score += factors["exploitability"]
        
        # Factor 3: Remediation Progress (25 points)
        if "Status" in self.df.columns:
            resolved_pct = (len(self.df[self.df["Status"].str.contains("Resolved|Fixed|Closed", case=False, na=False)]) / len(self.df)) * 100
            factors["remediation_progress"] = resolved_pct * 0.25
            maturity_score += factors["remediation_progress"]
        
        # Factor 4: Process Efficiency (25 points)
        tickets_created = len(self.df[self.df["Security Ticket"].notna()])
        ticket_creation_rate = (tickets_created / len(self.df)) * 100
        factors["process_efficiency"] = ticket_creation_rate * 0.25
        maturity_score += factors["process_efficiency"]
        
        # Overall maturity assessment
        if maturity_score >= 80:
            maturity_level = "Advanced"
        elif maturity_score >= 60:
            maturity_level = "Mature"
        elif maturity_score >= 40:
            maturity_level = "Developing"
        else:
            maturity_level = "Basic"
        
        return {
            "overall_score": maturity_score,
            "max_score": max_score,
            "maturity_level": maturity_level,
            "factors": factors,
            "recommendations": self._get_maturity_recommendations(maturity_score, factors)
        }
    
    def _get_maturity_recommendations(self, score: float, factors: Dict) -> List[str]:
        """Get recommendations based on maturity score"""
        recommendations = []
        
        if score < 40:
            recommendations.extend([
                "Implement basic security scanning and vulnerability management",
                "Establish security policies and procedures",
                "Begin security awareness training",
                "Set up basic incident response processes"
            ])
        elif score < 60:
            recommendations.extend([
                "Enhance vulnerability remediation processes",
                "Implement automated security testing",
                "Improve risk assessment methodologies",
                "Strengthen development security practices"
            ])
        elif score < 80:
            recommendations.extend([
                "Optimize security metrics and reporting",
                "Implement advanced threat modeling",
                "Enhance security automation and orchestration",
                "Develop security champions program"
            ])
        else:
            recommendations.extend([
                "Focus on continuous improvement and optimization",
                "Implement advanced security analytics",
                "Develop predictive security capabilities",
                "Establish security excellence programs"
            ])
        
        return recommendations
    
    def analyze_attack_vectors(self) -> Dict:
        """Analyze attack vectors and patterns"""
        if self.df.empty or "Vulnerability Name" not in self.df.columns:
            return {}
        
        vuln_names = self.df["Vulnerability Name"].dropna()
        
        # Define attack vector patterns
        attack_vectors = {
            "Injection Attacks": {
                "patterns": [r"sql.*injection|sqli|sql.*inject", r"nosql.*injection", r"ldap.*injection", r"command.*injection"],
                "description": "Code injection vulnerabilities"
            },
            "Cross-Site Scripting": {
                "patterns": [r"xss|cross.*site.*scripting|script.*injection", r"dom.*xss", r"reflected.*xss", r"stored.*xss"],
                "description": "Client-side script injection"
            },
            "Authentication Bypass": {
                "patterns": [r"auth.*bypass|authentication.*bypass|login.*bypass", r"weak.*password", r"default.*credential"],
                "description": "Authentication mechanism weaknesses"
            },
            "Authorization Issues": {
                "patterns": [r"authorization|permission|access.*control|privilege.*escalation", r"idor|direct.*object.*reference"],
                "description": "Access control vulnerabilities"
            },
            "Path Traversal": {
                "patterns": [r"path.*traversal|directory.*traversal|../|\.\./", r"file.*inclusion", r"local.*file.*inclusion"],
                "description": "File system access vulnerabilities"
            },
            "Security Misconfiguration": {
                "patterns": [r"misconfiguration|configuration|default.*setting", r"exposed.*service", r"unnecessary.*feature"],
                "description": "Configuration weaknesses"
            },
            "Sensitive Data Exposure": {
                "patterns": [r"exposure|sensitive.*data|password.*exposure|token.*exposure", r"data.*leak", r"information.*disclosure"],
                "description": "Data protection failures"
            },
            "Insecure Deserialization": {
                "patterns": [r"deserialization|unserialize|pickle", r"object.*injection", r"type.*confusion"],
                "description": "Object serialization vulnerabilities"
            }
        }
        
        vector_analysis = {}
        for vector_name, vector_info in attack_vectors.items():
            count = 0
            for pattern in vector_info["patterns"]:
                count += len(vuln_names[vuln_names.str.contains(pattern, case=False, regex=True)])
            vector_analysis[vector_name] = {
                "count": count,
                "percentage": (count / len(vuln_names)) * 100 if len(vuln_names) > 0 else 0,
                "description": vector_info["description"]
            }
        
        # Filter out zero counts
        vector_analysis = {k: v for k, v in vector_analysis.items() if v["count"] > 0}
        
        return {
            "attack_vectors": vector_analysis,
            "total_vulnerabilities": len(vuln_names),
            "vector_diversity": len(vector_analysis),
            "most_common_vector": max(vector_analysis.items(), key=lambda x: x[1]["count"])[0] if vector_analysis else None
        }
    
    def analyze_technology_risks(self) -> Dict:
        """Analyze technology-specific security risks"""
        if self.df.empty or "File Name (FullPath)" not in self.df.columns:
            return {}
        
        file_paths = self.df["File Name (FullPath)"].dropna()
        
        # Technology mapping
        technology_risks = {
            "JavaScript/TypeScript": {
                "extensions": ["js", "ts", "jsx", "tsx"],
                "common_vulns": ["XSS", "CSRF", "Insecure Deserialization"],
                "risk_level": "High"
            },
            "Python": {
                "extensions": ["py", "pyc", "pyo"],
                "common_vulns": ["Code Injection", "Path Traversal", "Insecure Deserialization"],
                "risk_level": "Medium"
            },
            "Java": {
                "extensions": ["java", "class", "jar"],
                "common_vulns": ["SQL Injection", "Deserialization", "Access Control"],
                "risk_level": "Medium"
            },
            "PHP": {
                "extensions": ["php", "phtml"],
                "common_vulns": ["SQL Injection", "File Inclusion", "XSS"],
                "risk_level": "High"
            },
            "C/C++": {
                "extensions": ["c", "cpp", "h", "hpp"],
                "common_vulns": ["Buffer Overflow", "Memory Corruption", "Integer Overflow"],
                "risk_level": "Critical"
            },
            "C#": {
                "extensions": ["cs", "dll"],
                "common_vulns": ["SQL Injection", "XSS", "Access Control"],
                "risk_level": "Medium"
            },
            "Ruby": {
                "extensions": ["rb", "erb"],
                "common_vulns": ["Code Injection", "Path Traversal", "XSS"],
                "risk_level": "Medium"
            },
            "Go": {
                "extensions": ["go"],
                "common_vulns": ["Path Traversal", "Command Injection", "Access Control"],
                "risk_level": "Low"
            },
            "Rust": {
                "extensions": ["rs"],
                "common_vulns": ["Logic Errors", "Access Control"],
                "risk_level": "Low"
            }
        }
        
        # Analyze file extensions
        extensions = []
        for path in file_paths:
            if '.' in str(path):
                ext = str(path).split('.')[-1].lower()
                extensions.append(ext)
        
        ext_counts = Counter(extensions)
        
        # Map to technologies
        tech_analysis = {}
        for tech_name, tech_info in technology_risks.items():
            count = sum(ext_counts.get(ext, 0) for ext in tech_info["extensions"])
            if count > 0:
                tech_analysis[tech_name] = {
                    "count": count,
                    "percentage": (count / len(extensions)) * 100 if extensions else 0,
                    "risk_level": tech_info["risk_level"],
                    "common_vulnerabilities": tech_info["common_vulns"]
                }
        
        return {
            "technology_analysis": tech_analysis,
            "total_files": len(file_paths),
            "unique_technologies": len(tech_analysis),
            "high_risk_technologies": [tech for tech, info in tech_analysis.items() if info["risk_level"] in ["High", "Critical"]]
        }
    
    def generate_predictive_insights(self) -> Dict:
        """Generate predictive insights based on current data"""
        if self.df.empty:
            return {}
        
        insights = {}
        
        # Predict remediation time based on severity and exploitability
        if "Severity" in self.df.columns and "Exploitable(%)" in self.df.columns:
            severity_map = {"Critical": 4, "High": 3, "Medium": 2, "Low": 1}
            self.df["severity_numeric"] = self.df["Severity"].map(severity_map)
            
            exp_col = self.df["Exploitable(%)"].astype(str).str.replace('%', '').str.replace(',', '')
            exp_numeric = pd.to_numeric(exp_col, errors='coerce')
            
            # Simple prediction model
            high_risk_count = len(self.df[(self.df["severity_numeric"] >= 3) & (exp_numeric >= 50)])
            insights["predicted_remediation_time"] = f"{high_risk_count * 2} days" if high_risk_count > 0 else "1-2 weeks"
            insights["high_priority_count"] = high_risk_count
        
        # Predict security posture improvement
        if "Status" in self.df.columns:
            resolved_count = len(self.df[self.df["Status"].str.contains("Resolved|Fixed|Closed", case=False, na=False)])
            total_count = len(self.df)
            current_rate = (resolved_count / total_count) * 100 if total_count > 0 else 0
            
            if current_rate < 30:
                insights["posture_improvement"] = "Significant improvement needed"
                insights["recommended_actions"] = ["Implement automated scanning", "Enhance remediation processes"]
            elif current_rate < 60:
                insights["posture_improvement"] = "Moderate improvement possible"
                insights["recommended_actions"] = ["Optimize workflows", "Improve team coordination"]
            else:
                insights["posture_improvement"] = "Maintain current practices"
                insights["recommended_actions"] = ["Continuous monitoring", "Advanced threat modeling"]
        
        # Predict vulnerability trends
        if "Vulnerability Name" in self.df.columns:
            vuln_counts = self.df["Vulnerability Name"].value_counts()
            most_common = vuln_counts.head(3).index.tolist()
            insights["predicted_focus_areas"] = most_common
            insights["trend_prediction"] = "Stable" if len(vuln_counts) < 10 else "Increasing diversity"
        
        return insights
    
    def create_advanced_visualizations(self) -> Dict:
        """Create advanced security analytics visualizations"""
        charts = {}
        
        # Security Maturity Radar Chart
        maturity_data = self.calculate_security_maturity_score()
        if maturity_data and "factors" in maturity_data:
            factors = maturity_data["factors"]
            if factors:
                fig = go.Figure()
                
                fig.add_trace(go.Scatterpolar(
                    r=list(factors.values()),
                    theta=list(factors.keys()),
                    fill='toself',
                    name='Current Score'
                ))
                
                fig.update_layout(
                    polar=dict(
                        radialaxis=dict(
                            visible=True,
                            range=[0, 25]
                        )),
                    showlegend=True,
                    title="Security Maturity Assessment"
                )
                charts["maturity_radar"] = fig
        
        # Attack Vector Analysis
        attack_vectors = self.analyze_attack_vectors()
        if attack_vectors and "attack_vectors" in attack_vectors:
            vectors = attack_vectors["attack_vectors"]
            if vectors:
                fig = px.bar(
                    x=list(vectors.keys()),
                    y=[v["count"] for v in vectors.values()],
                    title="Attack Vector Distribution",
                    labels={'x': 'Attack Vector', 'y': 'Count'}
                )
                charts["attack_vectors"] = fig
        
        # Technology Risk Heatmap
        tech_risks = self.analyze_technology_risks()
        if tech_risks and "technology_analysis" in tech_risks:
            tech_data = tech_risks["technology_analysis"]
            if tech_data:
                risk_levels = {"Low": 1, "Medium": 2, "High": 3, "Critical": 4}
                
                fig = px.scatter(
                    x=list(tech_data.keys()),
                    y=[tech_data[tech]["count"] for tech in tech_data.keys()],
                    size=[risk_levels.get(tech_data[tech]["risk_level"], 1) for tech in tech_data.keys()],
                    color=[tech_data[tech]["risk_level"] for tech in tech_data.keys()],
                    title="Technology Risk Analysis",
                    labels={'x': 'Technology', 'y': 'File Count', 'size': 'Risk Level', 'color': 'Risk Level'}
                )
                charts["technology_risks"] = fig
        
        # Trend Analysis
        trends = self.analyze_security_trends()
        if trends and "severity_distribution" in trends:
            severity_data = trends["severity_distribution"]
            if severity_data:
                fig = px.pie(
                    values=list(severity_data.values()),
                    names=list(severity_data.keys()),
                    title="Security Trend Analysis",
                    color_discrete_map={
                        "Critical": "#d62728",
                        "High": "#ff7f0e",
                        "Medium": "#ffec8b",
                        "Low": "#2ca02c"
                    }
                )
                charts["trend_analysis"] = fig
        
        return charts
    
    def generate_comprehensive_report(self) -> str:
        """Generate comprehensive security analytics report"""
        trends = self.analyze_security_trends()
        maturity = self.calculate_security_maturity_score()
        attack_vectors = self.analyze_attack_vectors()
        tech_risks = self.analyze_technology_risks()
        insights = self.generate_predictive_insights()
        
        report = f"""
# 🔒 Security Analytics Report

## 📊 Executive Summary
- **Total Vulnerabilities Analyzed:** {len(self.df)}
- **Security Maturity Level:** {maturity.get('maturity_level', 'N/A')}
- **Overall Maturity Score:** {maturity.get('overall_score', 0):.1f}/100
- **Risk Trend:** {trends.get('risk_trend', 'N/A')}

## 🎯 Key Security Insights

### Risk Assessment
- **Average Risk Score:** {trends.get('avg_risk_score', 0):.2f}/4.0
- **Highly Exploitable:** {trends.get('highly_exploitable_pct', 0):.1f}%
- **Exploitability Trend:** {trends.get('exploitability_trend', 'N/A')}

### Attack Vector Analysis
"""
        
        if attack_vectors and "attack_vectors" in attack_vectors:
            vectors = attack_vectors["attack_vectors"]
            for vector_name, vector_data in vectors.items():
                report += f"- **{vector_name}:** {vector_data['count']} instances ({vector_data['percentage']:.1f}%)\n"
        
        report += f"""
### Technology Risk Assessment
"""
        
        if tech_risks and "technology_analysis" in tech_risks:
            tech_data = tech_risks["technology_analysis"]
            for tech_name, tech_info in tech_data.items():
                report += f"- **{tech_name}:** {tech_info['count']} files ({tech_info['risk_level']} risk)\n"
        
        report += f"""
## 📈 Predictive Insights
- **Predicted Remediation Time:** {insights.get('predicted_remediation_time', 'N/A')}
- **Posture Improvement:** {insights.get('posture_improvement', 'N/A')}
- **High Priority Items:** {insights.get('high_priority_count', 0)}

## 🚀 Recommendations

### Immediate Actions
"""
        
        if maturity and "recommendations" in maturity:
            for i, rec in enumerate(maturity["recommendations"][:3], 1):
                report += f"{i}. {rec}\n"
        
        report += f"""
### Technology-Specific Actions
"""
        
        if tech_risks and "high_risk_technologies" in tech_risks:
            for tech in tech_risks["high_risk_technologies"]:
                report += f"- **{tech}:** Implement additional security controls and training\n"
        
        report += f"""
### Long-term Strategy
- Implement continuous security monitoring
- Develop security automation capabilities
- Establish security metrics and KPIs
- Create security awareness programs
"""
        
        return report

def display_security_analytics(excel_file_path: str, sheet_name: str = "Sheet1"):
    """Display comprehensive security analytics"""
    
    st.header("🔒 Security Analytics Dashboard")
    st.subheader("Advanced Analytics for Security Professionals")
    
    # Initialize analytics
    analytics = SecurityAnalytics(excel_file_path, sheet_name)
    
    if analytics.df.empty:
        st.error("❌ No data loaded. Please check the Excel file path.")
        return
    
    # Display analytics overview
    st.subheader("📊 Analytics Overview")
    
    trends = analytics.analyze_security_trends()
    maturity = analytics.calculate_security_maturity_score()
    
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        st.metric("Total Vulnerabilities", len(analytics.df))
        st.metric("Risk Trend", trends.get('risk_trend', 'N/A'))
    with col2:
        st.metric("Maturity Level", maturity.get('maturity_level', 'N/A'))
        st.metric("Maturity Score", f"{maturity.get('overall_score', 0):.1f}/100")
    with col3:
        st.metric("Avg Risk Score", f"{trends.get('avg_risk_score', 0):.2f}/4.0")
        st.metric("Exploitability Trend", trends.get('exploitability_trend', 'N/A'))
    with col4:
        st.metric("Vulnerability Diversity", trends.get('vulnerability_diversity', 'N/A'))
        st.metric("Attack Vectors", len(analytics.analyze_attack_vectors().get('attack_vectors', {})))
    
    # Create analytics tabs
    tab1, tab2, tab3, tab4, tab5 = st.tabs([
        "📈 Trend Analysis", 
        "🎯 Attack Vectors", 
        "💻 Technology Risks", 
        "🔮 Predictive Insights",
        "📊 Advanced Visualizations"
    ])
    
    with tab1:
        st.subheader("📈 Security Trend Analysis")
        
        if trends:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Severity Distribution:**")
                for severity, count in trends.get('severity_distribution', {}).items():
                    st.write(f"- {severity}: {count}")
            
            with col2:
                st.write("**Trend Metrics:**")
                st.metric("Average Risk Score", f"{trends.get('avg_risk_score', 0):.2f}")
                st.metric("Highly Exploitable %", f"{trends.get('highly_exploitable_pct', 0):.1f}%")
                st.metric("Vulnerability Diversity", trends.get('vulnerability_diversity', 'N/A'))
    
    with tab2:
        st.subheader("🎯 Attack Vector Analysis")
        
        attack_vectors = analytics.analyze_attack_vectors()
        if attack_vectors and "attack_vectors" in attack_vectors:
            vectors = attack_vectors["attack_vectors"]
            
            for vector_name, vector_data in vectors.items():
                with st.expander(f"🔍 {vector_name} ({vector_data['count']} instances)"):
                    st.write(f"**Description:** {vector_data['description']}")
                    st.write(f"**Percentage:** {vector_data['percentage']:.1f}%")
                    st.progress(vector_data['percentage'] / 100)
    
    with tab3:
        st.subheader("💻 Technology Risk Analysis")
        
        tech_risks = analytics.analyze_technology_risks()
        if tech_risks and "technology_analysis" in tech_risks:
            tech_data = tech_risks["technology_analysis"]
            
            for tech_name, tech_info in tech_data.items():
                risk_color = {
                    "Low": "🟢",
                    "Medium": "🟡", 
                    "High": "🟠",
                    "Critical": "🔴"
                }.get(tech_info["risk_level"], "⚪")
                
                st.write(f"{risk_color} **{tech_name}:** {tech_info['count']} files ({tech_info['risk_level']} risk)")
                st.write(f"   Common vulnerabilities: {', '.join(tech_info['common_vulnerabilities'])}")
    
    with tab4:
        st.subheader("🔮 Predictive Insights")
        
        insights = analytics.generate_predictive_insights()
        if insights:
            col1, col2 = st.columns(2)
            with col1:
                st.write("**Predictions:**")
                st.metric("Remediation Time", insights.get('predicted_remediation_time', 'N/A'))
                st.metric("High Priority Items", insights.get('high_priority_count', 0))
            
            with col2:
                st.write("**Recommendations:**")
                for action in insights.get('recommended_actions', []):
                    st.write(f"- {action}")
    
    with tab5:
        st.subheader("📊 Advanced Visualizations")
        
        charts = analytics.create_advanced_visualizations()
        
        if "maturity_radar" in charts:
            st.plotly_chart(charts["maturity_radar"], use_container_width=True)
        
        if "attack_vectors" in charts:
            st.plotly_chart(charts["attack_vectors"], use_container_width=True)
        
        if "technology_risks" in charts:
            st.plotly_chart(charts["technology_risks"], use_container_width=True)
        
        if "trend_analysis" in charts:
            st.plotly_chart(charts["trend_analysis"], use_container_width=True)
    
    # Display comprehensive report
    with st.expander("📄 Comprehensive Security Analytics Report"):
        report = analytics.generate_comprehensive_report()
        st.markdown(report)
    
    # Download analytics as JSON
    if st.button("📥 Download Analytics Report"):
        import json
        comprehensive_analytics = {
            "trends": trends,
            "maturity": maturity,
            "attack_vectors": analytics.analyze_attack_vectors(),
            "technology_risks": analytics.analyze_technology_risks(),
            "predictive_insights": analytics.generate_predictive_insights()
        }
        analytics_json = json.dumps(comprehensive_analytics, indent=2, default=str)
        st.download_button(
            "📥 Download Analytics JSON",
            analytics_json,
            file_name=f"security_analytics_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json",
            mime="application/json"
        )

if __name__ == "__main__":
    # Example usage
    import sys
    if len(sys.argv) > 1:
        excel_file = sys.argv[1]
        sheet_name = sys.argv[2] if len(sys.argv) > 2 else "Sheet1"
        display_security_analytics(excel_file, sheet_name)
    else:
        print("Usage: python security_analytics.py <excel_file_path> [sheet_name]") 