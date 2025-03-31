rule Python_SuspiciousPackageMetadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package metadata patterns"
        confidence = 85
        severity = 80
    strings:
        $nonsense_desc = /[A-Za-z]{15,}\s+[A-Za-z]{15,}\s+[A-Za-z]{15,}/
        $random_email = /[A-Za-z]{5,}@gmail\.com/
        $random_author = /[A-Za-z]{5,}/
    condition:
        any of them and filesize < 10KB
}