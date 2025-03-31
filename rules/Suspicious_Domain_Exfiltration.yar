rule Suspicious_Domain_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious domains used for data exfiltration in Python code"
        confidence = 85
        severity = 90
    strings:
        $oastify_domain = "oastify.com"
        $http_request = /https?:\/\/[a-zA-Z0-9]{16,}\.oastify\.com/
    condition:
        any of them
}