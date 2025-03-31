rule Suspicious_DNS_Tunneling_URLs {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious DNS tunneling patterns in URLs"
        confidence = 95
        severity = 85
    strings:
        $dns_pattern1 = /oast-cn\.byted-dast\.com/
        $dns_pattern2 = /oast-row\.byted-dast\.com/
        $dns_pattern3 = /oast\.fun/
    condition:
        any of ($dns_pattern1, $dns_pattern2, $dns_pattern3)
}