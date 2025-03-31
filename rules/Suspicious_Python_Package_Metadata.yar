rule Suspicious_Python_Package_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package metadata with exfiltration warnings"
        confidence = 95
        severity = 85
    strings:
        $suspicious_description = /This package is a proof of concept.*test purposes only.*not malicious in any way.*will be deleted after the research/
        $high_version = "version='99.9.9'"
    condition:
        filesize < 10KB and 
        all of them
}