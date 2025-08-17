#!/usr/bin/env python3
"""
BCheck Validator and Testing System
Validates BCheck syntax, structure, and tests functionality.
"""

import yaml
import json
import re
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import logging
from dataclasses import dataclass
from enum import Enum

class ValidationLevel(Enum):
    """Validation levels for BChecks"""
    BASIC = "basic"
    SYNTAX = "syntax"
    STRUCTURE = "structure"
    FUNCTIONAL = "functional"

@dataclass
class ValidationResult:
    """Result of BCheck validation"""
    is_valid: bool
    errors: List[str]
    warnings: List[str]
    level: ValidationLevel
    file_path: Optional[str] = None

class BCheckValidator:
    """Validates BCheck files for syntax, structure, and functionality"""
    
    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self.required_fields = {
            "metadata": ["name", "author", "version", "description"],
            "given": ["then"],
            "expression": [],
            "then": []
        }
        
        self.valid_severities = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        self.valid_log_levels = ["LOW", "MEDIUM", "HIGH"]
        
    def validate_file(self, file_path: str, level: ValidationLevel = ValidationLevel.STRUCTURE) -> ValidationResult:
        """Validate a BCheck file"""
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                content = f.read()
                
            return self.validate_content(content, level, file_path)
            
        except Exception as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"Failed to read file: {str(e)}"],
                warnings=[],
                level=level,
                file_path=file_path
            )
    
    def validate_content(self, content: str, level: ValidationLevel = ValidationLevel.STRUCTURE, 
                        file_path: Optional[str] = None) -> ValidationResult:
        """Validate BCheck content"""
        errors = []
        warnings = []
        
        # Basic YAML parsing
        try:
            bcheck_data = yaml.safe_load(content)
        except yaml.YAMLError as e:
            return ValidationResult(
                is_valid=False,
                errors=[f"Invalid YAML syntax: {str(e)}"],
                warnings=[],
                level=level,
                file_path=file_path
            )
        
        # Structure validation
        structure_result = self._validate_structure(bcheck_data)
        errors.extend(structure_result.errors)
        warnings.extend(structure_result.warnings)
        
        if level == ValidationLevel.BASIC:
            return ValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
                level=level,
                file_path=file_path
            )
        
        # Syntax validation
        if "expression" in bcheck_data:
            syntax_result = self._validate_expression_syntax(bcheck_data["expression"])
            errors.extend(syntax_result.errors)
            warnings.extend(syntax_result.warnings)
        
        if level == ValidationLevel.SYNTAX:
            return ValidationResult(
                is_valid=len(errors) == 0,
                errors=errors,
                warnings=warnings,
                level=level,
                file_path=file_path
            )
        
        # Advanced structure validation
        advanced_result = self._validate_advanced_structure(bcheck_data)
        errors.extend(advanced_result.errors)
        warnings.extend(advanced_result.warnings)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=level,
            file_path=file_path
        )
    
    def _validate_structure(self, bcheck_data: Dict[str, Any]) -> ValidationResult:
        """Validate basic BCheck structure"""
        errors = []
        warnings = []
        
        # Check required top-level sections
        for section in self.required_fields.keys():
            if section not in bcheck_data:
                errors.append(f"Missing required section: {section}")
        
        # Validate metadata
        if "metadata" in bcheck_data:
            metadata_result = self._validate_metadata(bcheck_data["metadata"])
            errors.extend(metadata_result.errors)
            warnings.extend(metadata_result.warnings)
        
        # Validate given section
        if "given" in bcheck_data:
            given_result = self._validate_given_section(bcheck_data["given"])
            errors.extend(given_result.errors)
            warnings.extend(given_result.warnings)
        
        # Validate then section
        if "then" in bcheck_data:
            then_result = self._validate_then_section(bcheck_data["then"])
            errors.extend(then_result.errors)
            warnings.extend(then_result.warnings)
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.STRUCTURE
        )
    
    def _validate_metadata(self, metadata: Dict[str, Any]) -> ValidationResult:
        """Validate metadata section"""
        errors = []
        warnings = []
        
        # Check required fields
        for field in self.required_fields["metadata"]:
            if field not in metadata or not metadata[field]:
                errors.append(f"Missing required metadata field: {field}")
        
        # Validate severity
        if "severity" in metadata:
            if metadata["severity"] not in self.valid_severities:
                errors.append(f"Invalid severity: {metadata['severity']}. Must be one of {self.valid_severities}")
        
        # Validate version format
        if "version" in metadata:
            version = str(metadata["version"])
            if not re.match(r'^\d+\.\d+(\.\d+)?$', version):
                warnings.append(f"Version format should be semantic (e.g., 1.0 or 1.0.0): {version}")
        
        # Validate tags
        if "tags" in metadata and isinstance(metadata["tags"], list):
            if len(metadata["tags"]) == 0:
                warnings.append("Tags list is empty - consider adding relevant tags")
        
        # Validate references
        if "references" in metadata and isinstance(metadata["references"], list):
            for ref in metadata["references"]:
                if not ref.startswith(("http://", "https://", "https://")):
                    warnings.append(f"Reference should be a URL: {ref}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.STRUCTURE
        )
    
    def _validate_given_section(self, given: Dict[str, Any]) -> ValidationResult:
        """Validate given section"""
        errors = []
        warnings = []
        
        if "then" not in given:
            errors.append("Given section must contain 'then' field")
        elif not isinstance(given["then"], list):
            errors.append("Given.then must be a list")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.STRUCTURE
        )
    
    def _validate_then_section(self, then: List[Any]) -> ValidationResult:
        """Validate then section"""
        errors = []
        warnings = []
        
        if not isinstance(then, list):
            errors.append("Then section must be a list")
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                level=ValidationLevel.STRUCTURE
            )
        
        if len(then) == 0:
            warnings.append("Then section is empty - no actions defined")
        
        for i, action in enumerate(then):
            if not isinstance(action, dict):
                errors.append(f"Action {i} must be a dictionary")
                continue
            
            # Validate log actions
            if "log" in action:
                log_result = self._validate_log_action(action["log"])
                errors.extend(log_result.errors)
                warnings.extend(log_result.warnings)
            
            # Validate report actions
            elif "report" in action:
                report_result = self._validate_report_action(action["report"])
                errors.extend(report_result.errors)
                warnings.extend(report_result.warnings)
            
            else:
                warnings.append(f"Action {i} has unknown type - should be 'log' or 'report'")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.STRUCTURE
        )
    
    def _validate_log_action(self, log: Dict[str, Any]) -> ValidationResult:
        """Validate log action"""
        errors = []
        warnings = []
        
        required_fields = ["level", "output"]
        for field in required_fields:
            if field not in log:
                errors.append(f"Log action missing required field: {field}")
        
        if "level" in log and log["level"] not in self.valid_log_levels:
            errors.append(f"Invalid log level: {log['level']}. Must be one of {self.valid_log_levels}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.STRUCTURE
        )
    
    def _validate_report_action(self, report: Dict[str, Any]) -> ValidationResult:
        """Validate report action"""
        errors = []
        warnings = []
        
        required_fields = ["issue", "severity", "confidence", "detail", "remediation"]
        for field in required_fields:
            if field not in report:
                errors.append(f"Report action missing required field: {field}")
        
        if "severity" in report and report["severity"] not in self.valid_severities:
            errors.append(f"Invalid report severity: {report['severity']}. Must be one of {self.valid_severities}")
        
        valid_confidence = ["LOW", "MEDIUM", "HIGH"]
        if "confidence" in report and report["confidence"] not in valid_confidence:
            errors.append(f"Invalid confidence: {report['confidence']}. Must be one of {valid_confidence}")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.STRUCTURE
        )
    
    def _validate_expression_syntax(self, expression: str) -> ValidationResult:
        """Validate expression syntax"""
        errors = []
        warnings = []
        
        if not expression or not expression.strip():
            errors.append("Expression is empty")
            return ValidationResult(
                is_valid=False,
                errors=errors,
                warnings=warnings,
                level=ValidationLevel.SYNTAX
            )
        
        # Check for common syntax issues
        lines = expression.split('\n')
        for i, line in enumerate(lines, 1):
            line = line.strip()
            if not line or line.startswith('//'):
                continue
            
            # Check for missing semicolons (common issue)
            if line and not line.endswith(';') and not line.endswith('{') and not line.endswith('}') and not line.endswith('(') and not line.endswith(')'):
                if 'let ' in line or 'return ' in line:
                    warnings.append(f"Line {i}: Consider adding semicolon at end of statement")
            
            # Check for common typos
            if 'request.' in line and 'request.' not in line:
                warnings.append(f"Line {i}: Check for typos in 'request.' references")
            
            if 'response.' in line and 'response.' not in line:
                warnings.append(f"Line {i}: Check for typos in 'response.' references")
        
        # Check for balanced braces
        open_braces = expression.count('{')
        close_braces = expression.count('}')
        if open_braces != close_braces:
            errors.append(f"Unbalanced braces: {open_braces} open, {close_braces} close")
        
        # Check for balanced parentheses
        open_parens = expression.count('(')
        close_parens = expression.count(')')
        if open_parens != close_parens:
            errors.append(f"Unbalanced parentheses: {open_parens} open, {close_parens} close")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.SYNTAX
        )
    
    def _validate_advanced_structure(self, bcheck_data: Dict[str, Any]) -> ValidationResult:
        """Validate advanced BCheck structure and patterns"""
        errors = []
        warnings = []
        
        # Check for common patterns
        if "expression" in bcheck_data:
            expression = bcheck_data["expression"]
            
            # Check for proper request handling
            if "request." in expression and "send(" not in expression:
                warnings.append("Expression references request but doesn't use send() - consider if this is intentional")
            
            # Check for proper response handling
            if "response." in expression and "send(" not in expression:
                warnings.append("Expression references response but doesn't use send() - consider if this is intentional")
            
            # Check for proper return statements
            if "return true" not in expression and "return false" not in expression:
                warnings.append("Expression should return true/false for vulnerability detection")
        
        return ValidationResult(
            is_valid=len(errors) == 0,
            errors=errors,
            warnings=warnings,
            level=ValidationLevel.STRUCTURE
        )
    
    def validate_directory(self, directory_path: str, level: ValidationLevel = ValidationLevel.STRUCTURE) -> List[ValidationResult]:
        """Validate all BCheck files in a directory"""
        results = []
        directory = Path(directory_path)
        
        if not directory.exists():
            self.logger.error(f"Directory does not exist: {directory_path}")
            return results
        
        for bcheck_file in directory.glob("*.bcheck"):
            result = self.validate_file(str(bcheck_file), level)
            results.append(result)
        
        return results
    
    def generate_validation_report(self, results: List[ValidationResult]) -> str:
        """Generate a comprehensive validation report"""
        total_files = len(results)
        valid_files = sum(1 for r in results if r.is_valid)
        total_errors = sum(len(r.errors) for r in results)
        total_warnings = sum(len(r.warnings) for r in results)
        
        report = f"""
BCheck Validation Report
=======================

Summary:
- Total files: {total_files}
- Valid files: {valid_files}
- Invalid files: {total_files - valid_files}
- Total errors: {total_errors}
- Total warnings: {total_warnings}

"""
        
        # Group by validation status
        valid_results = [r for r in results if r.is_valid]
        invalid_results = [r for r in results if not r.is_valid]
        
        if invalid_results:
            report += "Invalid Files:\n"
            report += "-" * 50 + "\n"
            for result in invalid_results:
                report += f"\nFile: {result.file_path or 'Unknown'}\n"
                report += f"Level: {result.level.value}\n"
                report += "Errors:\n"
                for error in result.errors:
                    report += f"  - {error}\n"
                if result.warnings:
                    report += "Warnings:\n"
                    for warning in result.warnings:
                        report += f"  - {warning}\n"
        
        if valid_results:
            report += f"\nValid Files ({len(valid_results)}):\n"
            report += "-" * 50 + "\n"
            for result in valid_results:
                report += f"- {result.file_path or 'Unknown'}\n"
                if result.warnings:
                    report += "  Warnings:\n"
                    for warning in result.warnings:
                        report += f"    - {warning}\n"
        
        return report

def main():
    """Main function for command-line usage"""
    import argparse
    
    parser = argparse.ArgumentParser(description="BCheck Validator")
    parser.add_argument("path", help="File or directory to validate")
    parser.add_argument("--level", choices=["basic", "syntax", "structure"], 
                       default="structure", help="Validation level")
    parser.add_argument("--output", help="Output file for report")
    
    args = parser.parse_args()
    
    validator = BCheckValidator()
    level = ValidationLevel(args.level)
    
    path = Path(args.path)
    if path.is_file():
        results = [validator.validate_file(str(path), level)]
    elif path.is_dir():
        results = validator.validate_directory(str(path), level)
    else:
        print(f"Error: {path} is not a valid file or directory")
        return
    
    report = validator.generate_validation_report(results)
    
    if args.output:
        with open(args.output, 'w') as f:
            f.write(report)
        print(f"Report saved to {args.output}")
    else:
        print(report)

if __name__ == "__main__":
    main()
