rule Python_HTTPRequest_WithParams {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests with parameters in Python code, commonly used for data exfiltration"
        confidence = 80
        severity = 70

    strings:
        // Detect HTTP requests with parameters
        $http_request = /requests\.get\s*\(.*params\s*=/

    condition:
        // Match if an HTTP request with parameters is found
        $http_request
}