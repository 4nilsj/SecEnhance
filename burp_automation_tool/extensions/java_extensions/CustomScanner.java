package burp.automation;

import burp.*;
import java.io.PrintWriter;
import java.util.List;
import java.util.ArrayList;

public class CustomScanner implements IBurpExtender, IScannerCheck {
    
    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;
    private PrintWriter stdout;
    private PrintWriter stderr;
    
    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);
        
        // Set extension name
        callbacks.setExtensionName("Custom Security Scanner");
        
        // Register scanner check
        callbacks.registerScannerCheck(this);
        
        stdout.println("Custom Security Scanner loaded successfully!");
    }
    
    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        List<IScanIssue> issues = new ArrayList<>();
        
        // Get request and response
        IRequestInfo requestInfo = helpers.analyzeRequest(baseRequestResponse);
        IResponseInfo responseInfo = helpers.analyzeResponse(baseRequestResponse.getResponse());
        
        // Check for security headers
        checkSecurityHeaders(baseRequestResponse, responseInfo, issues);
        
        // Check for sensitive information exposure
        checkSensitiveInfo(baseRequestResponse, responseInfo, issues);
        
        return issues;
    }
    
    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        List<IScanIssue> issues = new ArrayList<>();
        
        // SQL Injection test
        testSQLInjection(baseRequestResponse, insertionPoint, issues);
        
        // XSS test
        testXSS(baseRequestResponse, insertionPoint, issues);
        
        return issues;
    }
    
    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        // Return -1 if new issue is more severe
        if (newIssue.getSeverity().equals("High") && !existingIssue.getSeverity().equals("High")) {
            return -1;
        }
        // Return 1 if existing issue is more severe
        else if (existingIssue.getSeverity().equals("High") && !newIssue.getSeverity().equals("High")) {
            return 1;
        }
        // Return 0 if same severity
        return 0;
    }
    
    private void checkSecurityHeaders(IHttpRequestResponse baseRequestResponse, IResponseInfo responseInfo, List<IScanIssue> issues) {
        List<String> headers = responseInfo.getHeaders();
        
        boolean hasHSTS = false;
        boolean hasCSP = false;
        boolean hasXFrameOptions = false;
        
        for (String header : headers) {
            if (header.toLowerCase().startsWith("strict-transport-security:")) {
                hasHSTS = true;
            }
            if (header.toLowerCase().startsWith("content-security-policy:")) {
                hasCSP = true;
            }
            if (header.toLowerCase().startsWith("x-frame-options:")) {
                hasXFrameOptions = true;
            }
        }
        
        if (!hasHSTS) {
            issues.add(new CustomScanIssue(
                baseRequestResponse,
                "Missing HSTS Header",
                "The application does not include the Strict-Transport-Security header",
                "Medium"
            ));
        }
        
        if (!hasCSP) {
            issues.add(new CustomScanIssue(
                baseRequestResponse,
                "Missing CSP Header",
                "The application does not include the Content-Security-Policy header",
                "Medium"
            ));
        }
        
        if (!hasXFrameOptions) {
            issues.add(new CustomScanIssue(
                baseRequestResponse,
                "Missing X-Frame-Options Header",
                "The application does not include the X-Frame-Options header",
                "Low"
            ));
        }
    }
    
    private void checkSensitiveInfo(IHttpRequestResponse baseRequestResponse, IResponseInfo responseInfo, List<IScanIssue> issues) {
        String responseBody = helpers.bytesToString(baseRequestResponse.getResponse());
        
        // Check for common sensitive information patterns
        String[] sensitivePatterns = {
            "password", "api_key", "secret", "token", "private_key",
            "credit_card", "ssn", "social_security"
        };
        
        for (String pattern : sensitivePatterns) {
            if (responseBody.toLowerCase().contains(pattern)) {
                issues.add(new CustomScanIssue(
                    baseRequestResponse,
                    "Potential Sensitive Information Exposure",
                    "Response contains potential sensitive information: " + pattern,
                    "High"
                ));
            }
        }
    }
    
    private void testSQLInjection(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, List<IScanIssue> issues) {
        String[] sqlPayloads = {
            "' OR '1'='1",
            "' OR 1=1--",
            "'; DROP TABLE users--",
            "' UNION SELECT NULL--"
        };
        
        for (String payload : sqlPayloads) {
            byte[] modifiedRequest = insertionPoint.buildRequest(payload.getBytes());
            IHttpRequestResponse testRequest = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), modifiedRequest);
            
            String responseBody = helpers.bytesToString(testRequest.getResponse());
            
            // Check for SQL error messages
            if (responseBody.toLowerCase().contains("sql") || 
                responseBody.toLowerCase().contains("mysql") ||
                responseBody.toLowerCase().contains("oracle")) {
                
                issues.add(new CustomScanIssue(
                    testRequest,
                    "SQL Injection Vulnerability",
                    "SQL injection detected with payload: " + payload,
                    "High"
                ));
            }
        }
    }
    
    private void testXSS(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint, List<IScanIssue> issues) {
        String[] xssPayloads = {
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert('XSS')>",
            "javascript:alert('XSS')"
        };
        
        for (String payload : xssPayloads) {
            byte[] modifiedRequest = insertionPoint.buildRequest(payload.getBytes());
            IHttpRequestResponse testRequest = callbacks.makeHttpRequest(
                baseRequestResponse.getHttpService(), modifiedRequest);
            
            String responseBody = helpers.bytesToString(testRequest.getResponse());
            
            // Check if payload is reflected
            if (responseBody.contains(payload)) {
                issues.add(new CustomScanIssue(
                    testRequest,
                    "Cross-Site Scripting (XSS) Vulnerability",
                    "XSS vulnerability detected with payload: " + payload,
                    "High"
                ));
            }
        }
    }
    
    // Custom scan issue class
    private static class CustomScanIssue implements IScanIssue {
        private IHttpRequestResponse requestResponse;
        private String name;
        private String detail;
        private String severity;
        
        public CustomScanIssue(IHttpRequestResponse requestResponse, String name, String detail, String severity) {
            this.requestResponse = requestResponse;
            this.name = name;
            this.detail = detail;
            this.severity = severity;
        }
        
        @Override
        public String getUrl() {
            return requestResponse.getUrl().toString();
        }
        
        @Override
        public String getIssueName() {
            return name;
        }
        
        @Override
        public int getIssueType() {
            return 0;
        }
        
        @Override
        public String getSeverity() {
            return severity;
        }
        
        @Override
        public String getConfidence() {
            return "Certain";
        }
        
        @Override
        public String getIssueBackground() {
            return "This issue was detected by the Custom Security Scanner extension.";
        }
        
        @Override
        public String getRemediationBackground() {
            return "Review the application code and implement appropriate security measures.";
        }
        
        @Override
        public String getIssueDetail() {
            return detail;
        }
        
        @Override
        public String getRemediationDetail() {
            return "Implement proper input validation and output encoding.";
        }
        
        @Override
        public IHttpRequestResponse[] getHttpMessages() {
            return new IHttpRequestResponse[] { requestResponse };
        }
        
        @Override
        public IHttpService getHttpService() {
            return requestResponse.getHttpService();
        }
    }
} 