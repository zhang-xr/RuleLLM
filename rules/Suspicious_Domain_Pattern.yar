rule Suspicious_Domain_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects randomized or suspicious domain patterns in Python scripts"
        confidence = 85
        severity = 75
    strings:
        $domain_pattern = /https?:\/\/[a-z0-9]{16,}\.[a-z]{2,}/
    condition:
        $domain_pattern and
        filesize < 10KB
}