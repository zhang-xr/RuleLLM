rule Suspicious_Exfiltration_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL patterns used for exfiltration"
        confidence = 95
        severity = 90

    strings:
        $suspicious_url = /http:\/\/[a-zA-Z0-9]{20,}\.22\.ax\//

    condition:
        $suspicious_url
}