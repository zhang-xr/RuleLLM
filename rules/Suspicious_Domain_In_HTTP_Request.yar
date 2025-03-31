rule Suspicious_Domain_In_HTTP_Request {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious domain patterns in HTTP requests, often used in malicious payloads."
        confidence = 85
        severity = 80

    strings:
        $http_request = /requests\.get\(['\"].+?['\"]\)/
        $suspicious_domain = /[a-z0-9]{16,}\.(oastify|burpcollaborator|interactsh)\./

    condition:
        $http_request and $suspicious_domain
}