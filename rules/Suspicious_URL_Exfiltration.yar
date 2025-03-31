rule Suspicious_URL_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL patterns used for data exfiltration"
        confidence = 95
        severity = 85

    strings:
        $url_pattern = /http:\/\/[a-zA-Z0-9.-]+\.22\.ax\//

    condition:
        $url_pattern
}