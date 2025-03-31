rule Suspicious_OAST_Endpoint {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious OAST (Out-of-band Application Security Testing) style endpoints"
        confidence = 95
        severity = 85
    strings:
        $oast_url = /https?:\/\/[a-z0-9]{16,}\.oastify\.com/
    condition:
        $oast_url
}