rule Suspicious_Domain_Usage {
    meta:
        author = "RuleLLM"
        description = "Detects usage of suspicious domain for DNS queries"
        confidence = 95
        severity = 95
    strings:
        $suspicious_domain = ".ns.depcon.buzz"
    condition:
        $suspicious_domain
}