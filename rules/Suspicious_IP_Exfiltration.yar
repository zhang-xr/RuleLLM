rule Suspicious_IP_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects exfiltration to hardcoded IP addresses"
        confidence = 95
        severity = 85
    strings:
        $ip_pattern = /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $exfil_url = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\//
    condition:
        $exfil_url and $ip_pattern
}