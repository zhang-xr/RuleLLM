rule Exfiltration_URL_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URLs used for data exfiltration in Python scripts"
        confidence = 85
        severity = 75
    strings:
        $oast_domain = /https?:\/\/[a-zA-Z0-9]+\.oast\.fun/
    condition:
        $oast_domain
}