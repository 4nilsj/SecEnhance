"""
Architecture Parser for Threat Modeling Tool
Parses application architectures from various input formats.
"""

import re
import json
import yaml
from typing import Dict, List, Any, Optional
from pathlib import Path

from .debug_utils import debug_print, debug_log

class ArchitectureParser:
    """Parse application architectures from various input formats."""
    
    def __init__(self):
        """Initialize the architecture parser."""
        self.supported_formats = ['json', 'yaml', 'yml', 'txt', 'md']
    
    def parse_text_architecture(self, text: str) -> Dict[str, Any]:
        """Parse architecture from plain text description."""
        debug_log("parser", "Parsing text architecture")
        
        architecture = {
            "name": "",
            "description": "",
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
            "assets": []
        }
        
        lines = text.strip().split('\n')
        current_section = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            # Detect sections
            if line.lower().startswith('name:'):
                architecture["name"] = line.split(':', 1)[1].strip()
            elif line.lower().startswith('description:'):
                architecture["description"] = line.split(':', 1)[1].strip()
            elif line.lower().startswith('components:'):
                current_section = "components"
            elif line.lower().startswith('data flows:'):
                current_section = "data_flows"
            elif line.lower().startswith('trust boundaries:'):
                current_section = "trust_boundaries"
            elif line.lower().startswith('assets:'):
                current_section = "assets"
            elif line.startswith('-') or line.startswith('*'):
                # Parse list items
                self._parse_list_item(line, architecture, current_section)
        
        debug_log("parser", "Text architecture parsed", architecture)
        return architecture
    
    def _parse_list_item(self, line: str, architecture: Dict, section: str) -> None:
        """Parse a list item based on the current section."""
        if not section:
            return
        
        # Remove list markers
        content = re.sub(r'^[-*]\s*', '', line)
        
        if section == "components":
            component = self._parse_component(content)
            if component:
                architecture["components"].append(component)
        elif section == "data_flows":
            flow = self._parse_data_flow(content)
            if flow:
                architecture["data_flows"].append(flow)
        elif section == "trust_boundaries":
            boundary = self._parse_trust_boundary(content)
            if boundary:
                architecture["trust_boundaries"].append(boundary)
        elif section == "assets":
            asset = self._parse_asset(content)
            if asset:
                architecture["assets"].append(asset)
    
    def _parse_component(self, content: str) -> Optional[Dict]:
        """Parse component from text."""
        # Expected format: "name (type) - description"
        match = re.match(r'([^(]+)\s*\(([^)]+)\)\s*-\s*(.+)', content)
        if match:
            name, comp_type, description = match.groups()
            return {
                "name": name.strip(),
                "type": comp_type.strip(),
                "description": description.strip(),
                "technologies": [],
                "external": False
            }
        
        # Simple format: "name - description"
        match = re.match(r'([^-]+)\s*-\s*(.+)', content)
        if match:
            name, description = match.groups()
            return {
                "name": name.strip(),
                "type": "unknown",
                "description": description.strip(),
                "technologies": [],
                "external": False
            }
        
        return None
    
    def _parse_data_flow(self, content: str) -> Optional[Dict]:
        """Parse data flow from text."""
        # Expected format: "from -> to (protocol) - data_type"
        match = re.match(r'([^-]+)\s*->\s*([^(]+)\s*\(([^)]+)\)\s*-\s*(.+)', content)
        if match:
            from_comp, to_comp, protocol, data_type = match.groups()
            return {
                "from": from_comp.strip(),
                "to": to_comp.strip(),
                "protocol": protocol.strip(),
                "data_type": data_type.strip(),
                "encrypted": False
            }
        
        # Simple format: "from -> to"
        match = re.match(r'([^-]+)\s*->\s*(.+)', content)
        if match:
            from_comp, to_comp = match.groups()
            return {
                "from": from_comp.strip(),
                "to": to_comp.strip(),
                "protocol": "unknown",
                "data_type": "unknown",
                "encrypted": False
            }
        
        return None
    
    def _parse_trust_boundary(self, content: str) -> Optional[Dict]:
        """Parse trust boundary from text."""
        # Expected format: "name: components - description"
        match = re.match(r'([^:]+):\s*([^-]+)\s*-\s*(.+)', content)
        if match:
            name, components, description = match.groups()
            return {
                "name": name.strip(),
                "components": [c.strip() for c in components.split(',')],
                "description": description.strip()
            }
        
        return None
    
    def _parse_asset(self, content: str) -> Optional[Dict]:
        """Parse asset from text."""
        # Expected format: "name (type) - value - description"
        match = re.match(r'([^(]+)\s*\(([^)]+)\)\s*-\s*([^-]+)\s*-\s*(.+)', content)
        if match:
            name, asset_type, value, description = match.groups()
            return {
                "name": name.strip(),
                "type": asset_type.strip(),
                "value": value.strip(),
                "description": description.strip()
            }
        
        return None
    
    def parse_diagram_description(self, description: str) -> Dict[str, Any]:
        """Parse architecture from diagram description (Mermaid, PlantUML, etc.)."""
        debug_log("parser", "Parsing diagram description")
        
        architecture = {
            "name": "Diagram-based Architecture",
            "description": description[:100] + "..." if len(description) > 100 else description,
            "components": [],
            "data_flows": [],
            "trust_boundaries": [],
            "assets": []
        }
        
        # Extract components from diagram syntax
        component_patterns = [
            r'(\w+)\s*\[([^\]]+)\]',  # Mermaid: component[description]
            r'(\w+)\s*--\s*(\w+)',   # Connections
            r'(\w+)\s*->\s*(\w+)',   # Directed connections
        ]
        
        for pattern in component_patterns:
            matches = re.findall(pattern, description)
            for match in matches:
                if len(match) == 2:
                    if '[' in match[1]:  # Component
                        name, desc = match
                        architecture["components"].append({
                            "name": name.strip(),
                            "type": "unknown",
                            "description": desc.strip('[]'),
                            "technologies": [],
                            "external": False
                        })
                    else:  # Data flow
                        from_comp, to_comp = match
                        architecture["data_flows"].append({
                            "from": from_comp.strip(),
                            "to": to_comp.strip(),
                            "protocol": "unknown",
                            "data_type": "unknown",
                            "encrypted": False
                        })
        
        debug_log("parser", "Diagram description parsed", architecture)
        return architecture
    
    def validate_architecture(self, architecture: Dict[str, Any]) -> List[str]:
        """Validate architecture data and return list of issues."""
        debug_log("parser", "Validating architecture")
        
        issues = []
        
        # Check required fields
        if not architecture.get("name"):
            issues.append("Missing application name")
        
        if not architecture.get("components"):
            issues.append("No components defined")
        
        # Validate components
        for i, component in enumerate(architecture.get("components", [])):
            if not component.get("name"):
                issues.append(f"Component {i+1}: Missing name")
        
        # Validate data flows
        for i, flow in enumerate(architecture.get("data_flows", [])):
            if not flow.get("from") or not flow.get("to"):
                issues.append(f"Data flow {i+1}: Missing from/to components")
        
        # Check for orphaned data flows
        component_names = {c["name"] for c in architecture.get("components", [])}
        for flow in architecture.get("data_flows", []):
            if flow.get("from") not in component_names:
                issues.append(f"Data flow references unknown component: {flow.get('from')}")
            if flow.get("to") not in component_names:
                issues.append(f"Data flow references unknown component: {flow.get('to')}")
        
        debug_log("parser", f"Validation completed. Found {len(issues)} issues")
        return issues
    
    def enhance_architecture(self, architecture: Dict[str, Any]) -> Dict[str, Any]:
        """Enhance architecture with inferred information."""
        debug_log("parser", "Enhancing architecture with inferred data")
        
        enhanced = architecture.copy()
        
        # Infer component types if not specified
        for component in enhanced.get("components", []):
            if component.get("type") == "unknown":
                component["type"] = self._infer_component_type(component["name"])
        
        # Infer data flow protocols
        for flow in enhanced.get("data_flows", []):
            if flow.get("protocol") == "unknown":
                flow["protocol"] = self._infer_protocol(flow)
        
        # Add default trust boundaries
        if not enhanced.get("trust_boundaries"):
            enhanced["trust_boundaries"] = self._create_default_boundaries(enhanced)
        
        debug_log("parser", "Architecture enhancement completed")
        return enhanced
    
    def _infer_component_type(self, name: str) -> str:
        """Infer component type from name."""
        name_lower = name.lower()
        
        if any(word in name_lower for word in ['db', 'database', 'sql', 'mongo']):
            return "database"
        elif any(word in name_lower for word in ['api', 'service', 'microservice']):
            return "api"
        elif any(word in name_lower for word in ['web', 'frontend', 'ui', 'client']):
            return "web_server"
        elif any(word in name_lower for word in ['gateway', 'proxy', 'load']):
            return "gateway"
        else:
            return "service"
    
    def _infer_protocol(self, flow: Dict) -> str:
        """Infer protocol from data flow context."""
        from_comp = flow.get("from", "").lower()
        to_comp = flow.get("to", "").lower()
        
        if any(word in from_comp for word in ['web', 'frontend', 'client']):
            return "HTTPS"
        elif any(word in to_comp for word in ['db', 'database']):
            return "TCP"
        else:
            return "HTTP"
    
    def _create_default_boundaries(self, architecture: Dict[str, Any]) -> List[Dict]:
        """Create default trust boundaries."""
        boundaries = []
        
        # External boundary
        external_components = [c["name"] for c in architecture.get("components", []) 
                             if c.get("external", False)]
        if external_components:
            boundaries.append({
                "name": "External Systems",
                "components": external_components,
                "description": "External systems and third-party services"
            })
        
        # Internal boundary
        internal_components = [c["name"] for c in architecture.get("components", []) 
                             if not c.get("external", False)]
        if internal_components:
            boundaries.append({
                "name": "Internal Systems",
                "components": internal_components,
                "description": "Internal application components"
            })
        
        return boundaries 