"""
Kubernetes Security Analyzer
Comprehensive security analysis for Kubernetes manifests including RBAC, network policies, pod security standards, and configuration validation.
"""

import json
import logging
import os
import re
from pathlib import Path
from typing import Dict, List, Any, Optional

import yaml
from rich.console import Console

from ..utils.debug_utils import debug_print

class KubernetesAnalyzer:
    """Kubernetes security analyzer."""
    
    def __init__(self, debug: bool = False):
        """Initialize the Kubernetes analyzer."""
        self.debug = debug
        self.console = Console()
        
        # Pod Security Standards
        self.pod_security_standards = {
            "privileged": {
                "description": "Privileged pod security standard",
                "severity": "critical",
                "checks": self._check_privileged_standard
            },
            "baseline": {
                "description": "Baseline pod security standard",
                "severity": "medium",
                "checks": self._check_baseline_standard
            },
            "restricted": {
                "description": "Restricted pod security standard",
                "severity": "low",
                "checks": self._check_restricted_standard
            }
        }
        
        # Dangerous capabilities
        self.dangerous_capabilities = [
            "ALL", "SYS_ADMIN", "NET_ADMIN", "SYS_MODULE", "SYS_RAWIO",
            "SYS_PTRACE", "SYS_PACCT", "SYS_LEASE", "SYS_TIME", "SYS_TTY_CONFIG",
            "MKNOD", "AUDIT_WRITE", "AUDIT_CONTROL", "MAC_OVERRIDE", "MAC_ADMIN",
            "SYSLOG", "WAKE_ALARM", "BLOCK_SUSPEND", "DAC_OVERRIDE", "DAC_READ_SEARCH"
        ]
    
    def analyze_manifests(self, manifest_path: str) -> Dict[str, Any]:
        """Analyze Kubernetes manifests for security issues."""
        debug_print("Starting Kubernetes manifest analysis for:", manifest_path)
        
        results = {
            "manifest_path": manifest_path,
            "resources_found": [],
            "configuration_issues": [],
            "security_violations": [],
            "rbac_analysis": {},
            "network_analysis": {},
            "pod_security_analysis": {},
            "vulnerabilities": []
        }
        
        try:
            # Load and parse manifests
            manifests = self._load_manifests(manifest_path)
            results["resources_found"] = [m.get("kind", "Unknown") for m in manifests]
            
            # Analyze each manifest
            for manifest in manifests:
                manifest_analysis = self._analyze_manifest(manifest)
                
                # Merge results
                for key in ["configuration_issues", "security_violations", "vulnerabilities"]:
                    results[key].extend(manifest_analysis.get(key, []))
            
            # Perform specific analyses
            results["rbac_analysis"] = self.analyze_rbac(manifest_path)
            results["network_analysis"] = self.analyze_network_policies(manifest_path)
            results["pod_security_analysis"] = self.analyze_pod_security(manifest_path)
            
            # Generate vulnerability summary
            self._generate_kubernetes_vulnerability_summary(results)
            
        except Exception as e:
            debug_print("Error analyzing Kubernetes manifests:", str(e))
            results["error"] = str(e)
        
        return results
    
    def _load_manifests(self, manifest_path: str) -> List[Dict[str, Any]]:
        """Load and parse Kubernetes manifests."""
        manifests = []
        
        try:
            path = Path(manifest_path)
            
            if path.is_file():
                # Single file
                with open(path, 'r') as f:
                    content = f.read()
                    if '---' in content:
                        # Multiple documents
                        for doc in yaml.safe_load_all(content):
                            if doc:
                                manifests.append(doc)
                    else:
                        # Single document
                        doc = yaml.safe_load(content)
                        if doc:
                            manifests.append(doc)
            
            elif path.is_dir():
                # Directory - scan for YAML files
                for yaml_file in path.glob("*.yaml"):
                    with open(yaml_file, 'r') as f:
                        content = f.read()
                        if '---' in content:
                            for doc in yaml.safe_load_all(content):
                                if doc:
                                    manifests.append(doc)
                        else:
                            doc = yaml.safe_load(content)
                            if doc:
                                manifests.append(doc)
                
                for yaml_file in path.glob("*.yml"):
                    with open(yaml_file, 'r') as f:
                        content = f.read()
                        if '---' in content:
                            for doc in yaml.safe_load_all(content):
                                if doc:
                                    manifests.append(doc)
                        else:
                            doc = yaml.safe_load(content)
                            if doc:
                                manifests.append(doc)
            
        except Exception as e:
            debug_print("Error loading manifests:", str(e))
        
        return manifests
    
    def _analyze_manifest(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual Kubernetes manifest."""
        analysis = {
            "configuration_issues": [],
            "security_violations": [],
            "vulnerabilities": []
        }
        
        kind = manifest.get("kind", "")
        metadata = manifest.get("metadata", {})
        name = metadata.get("name", "unknown")
        
        debug_print(f"Analyzing {kind}: {name}")
        
        # Analyze based on resource type
        if kind == "Pod":
            pod_analysis = self._analyze_pod(manifest)
            analysis["security_violations"].extend(pod_analysis.get("violations", []))
            analysis["vulnerabilities"].extend(pod_analysis.get("vulnerabilities", []))
        
        elif kind == "Deployment":
            deployment_analysis = self._analyze_deployment(manifest)
            analysis["security_violations"].extend(deployment_analysis.get("violations", []))
            analysis["vulnerabilities"].extend(deployment_analysis.get("vulnerabilities", []))
        
        elif kind == "Service":
            service_analysis = self._analyze_service(manifest)
            analysis["security_violations"].extend(service_analysis.get("violations", []))
            analysis["vulnerabilities"].extend(service_analysis.get("vulnerabilities", []))
        
        elif kind == "ConfigMap":
            configmap_analysis = self._analyze_configmap(manifest)
            analysis["security_violations"].extend(configmap_analysis.get("violations", []))
            analysis["vulnerabilities"].extend(configmap_analysis.get("vulnerabilities", []))
        
        elif kind == "Secret":
            secret_analysis = self._analyze_secret(manifest)
            analysis["security_violations"].extend(secret_analysis.get("violations", []))
            analysis["vulnerabilities"].extend(secret_analysis.get("vulnerabilities", []))
        
        elif kind == "Role" or kind == "ClusterRole":
            role_analysis = self._analyze_role(manifest)
            analysis["security_violations"].extend(role_analysis.get("violations", []))
            analysis["vulnerabilities"].extend(role_analysis.get("vulnerabilities", []))
        
        elif kind == "RoleBinding" or kind == "ClusterRoleBinding":
            binding_analysis = self._analyze_role_binding(manifest)
            analysis["security_violations"].extend(binding_analysis.get("violations", []))
            analysis["vulnerabilities"].extend(binding_analysis.get("vulnerabilities", []))
        
        return analysis
    
    def _analyze_pod(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Pod manifest for security issues."""
        analysis = {
            "violations": [],
            "vulnerabilities": []
        }
        
        spec = manifest.get("spec", {})
        containers = spec.get("containers", [])
        
        # Check for privileged mode
        if spec.get("securityContext", {}).get("runAsNonRoot") is False:
            analysis["violations"].append({
                "type": "privileged_pod",
                "severity": "critical",
                "description": "Pod runs as root user",
                "impact": "Privilege escalation risk"
            })
        
        # Check for privileged containers
        for container in containers:
            security_context = container.get("securityContext", {})
            
            if security_context.get("privileged"):
                analysis["violations"].append({
                    "type": "privileged_container",
                    "severity": "critical",
                    "description": f"Container {container.get('name', 'unknown')} runs in privileged mode",
                    "impact": "Full host access"
                })
            
            # Check for dangerous capabilities
            capabilities = security_context.get("capabilities", {})
            add_capabilities = capabilities.get("add", [])
            
            for cap in add_capabilities:
                if cap in self.dangerous_capabilities:
                    analysis["violations"].append({
                        "type": "dangerous_capability",
                        "severity": "high",
                        "description": f"Container {container.get('name', 'unknown')} has dangerous capability: {cap}",
                        "impact": "Privilege escalation risk"
                    })
            
            # Check for host path mounts
            volume_mounts = container.get("volumeMounts", [])
            for mount in volume_mounts:
                if mount.get("mountPath") in ["/", "/etc", "/var/run", "/proc", "/sys"]:
                    analysis["violations"].append({
                        "type": "dangerous_mount",
                        "severity": "high",
                        "description": f"Container {container.get('name', 'unknown')} mounts sensitive host path: {mount.get('mountPath')}",
                        "impact": "Host file system access"
                    })
        
        return analysis
    
    def _analyze_deployment(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Deployment manifest for security issues."""
        analysis = {
            "violations": [],
            "vulnerabilities": []
        }
        
        spec = manifest.get("spec", {})
        template = spec.get("template", {})
        pod_spec = template.get("spec", {})
        
        # Check for replica count
        replicas = spec.get("replicas", 1)
        if replicas > 10:
            analysis["violations"].append({
                "type": "high_replica_count",
                "severity": "medium",
                "description": f"High replica count: {replicas}",
                "impact": "Resource exhaustion risk"
            })
        
        # Check for resource limits
        containers = pod_spec.get("containers", [])
        for container in containers:
            resources = container.get("resources", {})
            
            if not resources.get("limits"):
                analysis["violations"].append({
                    "type": "no_resource_limits",
                    "severity": "medium",
                    "description": f"Container {container.get('name', 'unknown')} has no resource limits",
                    "impact": "Resource exhaustion risk"
                })
            
            if not resources.get("requests"):
                analysis["violations"].append({
                    "type": "no_resource_requests",
                    "severity": "low",
                    "description": f"Container {container.get('name', 'unknown')} has no resource requests",
                    "impact": "Scheduling issues"
                })
        
        return analysis
    
    def _analyze_service(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Service manifest for security issues."""
        analysis = {
            "violations": [],
            "vulnerabilities": []
        }
        
        spec = manifest.get("spec", {})
        service_type = spec.get("type", "ClusterIP")
        
        # Check for LoadBalancer type
        if service_type == "LoadBalancer":
            analysis["violations"].append({
                "type": "loadbalancer_service",
                "severity": "medium",
                "description": "Service uses LoadBalancer type",
                "impact": "External exposure risk"
            })
        
        # Check for NodePort type
        if service_type == "NodePort":
            analysis["violations"].append({
                "type": "nodeport_service",
                "severity": "low",
                "description": "Service uses NodePort type",
                "impact": "Node-level exposure"
            })
        
        # Check for external IPs
        external_ips = spec.get("externalIPs", [])
        if external_ips:
            analysis["violations"].append({
                "type": "external_ips",
                "severity": "high",
                "description": f"Service has external IPs: {external_ips}",
                "impact": "Direct external access"
            })
        
        return analysis
    
    def _analyze_configmap(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze ConfigMap manifest for security issues."""
        analysis = {
            "violations": [],
            "vulnerabilities": []
        }
        
        data = manifest.get("data", {})
        
        # Check for sensitive data in ConfigMap
        sensitive_patterns = [
            r"password",
            r"secret",
            r"key",
            r"token",
            r"credential"
        ]
        
        for key, value in data.items():
            for pattern in sensitive_patterns:
                if re.search(pattern, key, re.IGNORECASE):
                    analysis["violations"].append({
                        "type": "sensitive_configmap",
                        "severity": "high",
                        "description": f"ConfigMap contains sensitive data: {key}",
                        "impact": "Secret exposure"
                    })
                    break
        
        return analysis
    
    def _analyze_secret(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Secret manifest for security issues."""
        analysis = {
            "violations": [],
            "vulnerabilities": []
        }
        
        # Check if secret is base64 encoded
        data = manifest.get("data", {})
        string_data = manifest.get("stringData", {})
        
        # Check for unencoded data
        if string_data:
            analysis["violations"].append({
                "type": "unencoded_secret",
                "severity": "medium",
                "description": "Secret contains unencoded stringData",
                "impact": "Potential data exposure"
            })
        
        return analysis
    
    def _analyze_role(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze Role/ClusterRole manifest for security issues."""
        analysis = {
            "violations": [],
            "vulnerabilities": []
        }
        
        rules = manifest.get("rules", [])
        
        for rule in rules:
            # Check for wildcard permissions
            resources = rule.get("resources", [])
            if "*" in resources:
                analysis["violations"].append({
                    "type": "wildcard_resources",
                    "severity": "high",
                    "description": "Role has wildcard resource permissions",
                    "impact": "Over-privileged access"
                })
            
            # Check for dangerous verbs
            verbs = rule.get("verbs", [])
            dangerous_verbs = ["*", "create", "delete", "deletecollection", "patch", "update"]
            
            for verb in verbs:
                if verb in dangerous_verbs:
                    analysis["violations"].append({
                        "type": "dangerous_verb",
                        "severity": "medium",
                        "description": f"Role has dangerous verb: {verb}",
                        "impact": "Modification permissions"
                    })
        
        return analysis
    
    def _analyze_role_binding(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze RoleBinding/ClusterRoleBinding manifest for security issues."""
        analysis = {
            "violations": [],
            "vulnerabilities": []
        }
        
        subjects = manifest.get("subjects", [])
        
        # Check for service account bindings
        for subject in subjects:
            if subject.get("kind") == "ServiceAccount":
                analysis["violations"].append({
                    "type": "service_account_binding",
                    "severity": "medium",
                    "description": f"Role bound to service account: {subject.get('name', 'unknown')}",
                    "impact": "Service account privilege escalation"
                })
        
        return analysis
    
    def analyze_rbac(self, manifest_path: str) -> Dict[str, Any]:
        """Analyze RBAC configuration for security issues."""
        debug_print("Analyzing RBAC configuration")
        
        analysis = {
            "roles_found": [],
            "role_bindings_found": [],
            "security_issues": [],
            "privilege_escalation_risks": []
        }
        
        try:
            manifests = self._load_manifests(manifest_path)
            
            for manifest in manifests:
                kind = manifest.get("kind", "")
                
                if kind in ["Role", "ClusterRole"]:
                    analysis["roles_found"].append({
                        "name": manifest.get("metadata", {}).get("name", "unknown"),
                        "kind": kind,
                        "rules": manifest.get("rules", [])
                    })
                
                elif kind in ["RoleBinding", "ClusterRoleBinding"]:
                    analysis["role_bindings_found"].append({
                        "name": manifest.get("metadata", {}).get("name", "unknown"),
                        "kind": kind,
                        "subjects": manifest.get("subjects", []),
                        "role_ref": manifest.get("roleRef", {})
                    })
            
            # Analyze for privilege escalation risks
            analysis["privilege_escalation_risks"] = self._analyze_privilege_escalation(analysis)
            
        except Exception as e:
            debug_print("Error analyzing RBAC:", str(e))
        
        return analysis
    
    def _analyze_privilege_escalation(self, rbac_analysis: Dict[str, Any]) -> List[Dict[str, Any]]:
        """Analyze for privilege escalation risks in RBAC."""
        risks = []
        
        # Check for cluster-admin bindings
        for binding in rbac_analysis["role_bindings_found"]:
            role_ref = binding.get("role_ref", {})
            if role_ref.get("name") == "cluster-admin":
                risks.append({
                    "type": "cluster_admin_binding",
                    "severity": "critical",
                    "description": f"Cluster-admin role bound to: {binding.get('name')}",
                    "impact": "Full cluster access"
                })
        
        # Check for wildcard permissions
        for role in rbac_analysis["roles_found"]:
            rules = role.get("rules", [])
            for rule in rules:
                if "*" in rule.get("resources", []) and "*" in rule.get("verbs", []):
                    risks.append({
                        "type": "wildcard_permissions",
                        "severity": "high",
                        "description": f"Role {role.get('name')} has wildcard permissions",
                        "impact": "Over-privileged access"
                    })
        
        return risks
    
    def analyze_network_policies(self, manifest_path: str) -> Dict[str, Any]:
        """Analyze network policies for security issues."""
        debug_print("Analyzing network policies")
        
        analysis = {
            "policies_found": [],
            "security_issues": [],
            "coverage_analysis": {}
        }
        
        try:
            manifests = self._load_manifests(manifest_path)
            
            for manifest in manifests:
                if manifest.get("kind") == "NetworkPolicy":
                    policy_analysis = self._analyze_network_policy(manifest)
                    analysis["policies_found"].append(policy_analysis)
                    analysis["security_issues"].extend(policy_analysis.get("issues", []))
            
            # Analyze network policy coverage
            analysis["coverage_analysis"] = self._analyze_network_coverage(analysis)
            
        except Exception as e:
            debug_print("Error analyzing network policies:", str(e))
        
        return analysis
    
    def _analyze_network_policy(self, manifest: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze individual network policy."""
        analysis = {
            "name": manifest.get("metadata", {}).get("name", "unknown"),
            "issues": []
        }
        
        spec = manifest.get("spec", {})
        
        # Check for overly permissive policies
        ingress = spec.get("ingress", [])
        for rule in ingress:
            if not rule.get("from"):
                analysis["issues"].append({
                    "type": "permissive_ingress",
                    "severity": "medium",
                    "description": "Ingress rule allows all sources",
                    "impact": "Unrestricted ingress traffic"
                })
        
        egress = spec.get("egress", [])
        for rule in egress:
            if not rule.get("to"):
                analysis["issues"].append({
                    "type": "permissive_egress",
                    "severity": "medium",
                    "description": "Egress rule allows all destinations",
                    "impact": "Unrestricted egress traffic"
                })
        
        return analysis
    
    def _analyze_network_coverage(self, analysis: Dict[str, Any]) -> Dict[str, Any]:
        """Analyze network policy coverage."""
        coverage = {
            "policies_count": len(analysis["policies_found"]),
            "coverage_percentage": 0,
            "unprotected_namespaces": []
        }
        
        # This would require cluster state analysis
        # For now, return basic metrics
        if coverage["policies_count"] == 0:
            coverage["coverage_percentage"] = 0
        elif coverage["policies_count"] < 5:
            coverage["coverage_percentage"] = 25
        else:
            coverage["coverage_percentage"] = 75
        
        return coverage
    
    def analyze_pod_security(self, manifest_path: str) -> Dict[str, Any]:
        """Analyze pod security standards compliance."""
        debug_print("Analyzing pod security standards")
        
        analysis = {
            "standards_compliance": {},
            "violations": []
        }
        
        try:
            manifests = self._load_manifests(manifest_path)
            
            for standard_name, standard_config in self.pod_security_standards.items():
                standard_analysis = standard_config["checks"](manifests)
                analysis["standards_compliance"][standard_name] = standard_analysis
                analysis["violations"].extend(standard_analysis.get("violations", []))
            
        except Exception as e:
            debug_print("Error analyzing pod security:", str(e))
        
        return analysis
    
    def _check_privileged_standard(self, manifests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check privileged pod security standard."""
        violations = []
        
        for manifest in manifests:
            if manifest.get("kind") in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]:
                spec = manifest.get("spec", {})
                template = spec.get("template", {})
                pod_spec = template.get("spec", {})
                
                # Check for privileged containers
                containers = pod_spec.get("containers", [])
                for container in containers:
                    security_context = container.get("securityContext", {})
                    if security_context.get("privileged"):
                        violations.append({
                            "type": "privileged_container",
                            "severity": "critical",
                            "description": f"Container {container.get('name', 'unknown')} is privileged",
                            "standard": "privileged"
                        })
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations
        }
    
    def _check_baseline_standard(self, manifests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check baseline pod security standard."""
        violations = []
        
        for manifest in manifests:
            if manifest.get("kind") in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]:
                spec = manifest.get("spec", {})
                template = spec.get("template", {})
                pod_spec = template.get("spec", {})
                
                # Check for host namespaces
                if pod_spec.get("hostPID") or pod_spec.get("hostIPC") or pod_spec.get("hostNetwork"):
                    violations.append({
                        "type": "host_namespace",
                        "severity": "high",
                        "description": "Pod uses host namespaces",
                        "standard": "baseline"
                    })
                
                # Check for privileged containers
                containers = pod_spec.get("containers", [])
                for container in containers:
                    security_context = container.get("securityContext", {})
                    if security_context.get("privileged"):
                        violations.append({
                            "type": "privileged_container",
                            "severity": "critical",
                            "description": f"Container {container.get('name', 'unknown')} is privileged",
                            "standard": "baseline"
                        })
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations
        }
    
    def _check_restricted_standard(self, manifests: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Check restricted pod security standard."""
        violations = []
        
        for manifest in manifests:
            if manifest.get("kind") in ["Pod", "Deployment", "StatefulSet", "DaemonSet"]:
                spec = manifest.get("spec", {})
                template = spec.get("template", {})
                pod_spec = template.get("spec", {})
                
                # Check for run as non-root
                security_context = pod_spec.get("securityContext", {})
                if security_context.get("runAsNonRoot") is not True:
                    violations.append({
                        "type": "run_as_root",
                        "severity": "high",
                        "description": "Pod does not enforce runAsNonRoot",
                        "standard": "restricted"
                    })
                
                # Check for read-only root filesystem
                containers = pod_spec.get("containers", [])
                for container in containers:
                    security_context = container.get("securityContext", {})
                    if not security_context.get("readOnlyRootFilesystem"):
                        violations.append({
                            "type": "writable_root_filesystem",
                            "severity": "medium",
                            "description": f"Container {container.get('name', 'unknown')} has writable root filesystem",
                            "standard": "restricted"
                        })
        
        return {
            "compliant": len(violations) == 0,
            "violations": violations
        }
    
    def _generate_kubernetes_vulnerability_summary(self, results: Dict[str, Any]):
        """Generate vulnerability summary for Kubernetes analysis."""
        if "vulnerabilities" not in results:
            results["vulnerabilities"] = []
        
        # Add issues from other analyses
        for issue_list in ["configuration_issues", "security_violations"]:
            if issue_list in results:
                results["vulnerabilities"].extend(results[issue_list])
        
        # Add RBAC issues
        rbac_analysis = results.get("rbac_analysis", {})
        results["vulnerabilities"].extend(rbac_analysis.get("privilege_escalation_risks", []))
        
        # Add network policy issues
        network_analysis = results.get("network_analysis", {})
        results["vulnerabilities"].extend(network_analysis.get("security_issues", []))
        
        # Add pod security violations
        pod_security_analysis = results.get("pod_security_analysis", {})
        results["vulnerabilities"].extend(pod_security_analysis.get("violations", []))
        
        # Categorize vulnerabilities
        critical = [v for v in results["vulnerabilities"] if v.get("severity") == "critical"]
        high = [v for v in results["vulnerabilities"] if v.get("severity") == "high"]
        medium = [v for v in results["vulnerabilities"] if v.get("severity") == "medium"]
        low = [v for v in results["vulnerabilities"] if v.get("severity") == "low"]
        
        results["vulnerability_summary"] = {
            "total": len(results["vulnerabilities"]),
            "critical": len(critical),
            "high": len(high),
            "medium": len(medium),
            "low": len(low)
        } 