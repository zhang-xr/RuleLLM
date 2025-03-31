rule Python_Suspicious_URL {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URLs in Python code, particularly those associated with OAST tools."
        confidence = 95
        severity = 90

    strings:
        $oastify_url = /https?:\/\/[a-z0-9]+\.oastify\.com/ nocase
        $webhook_url = /https?:\/\/webhook\.site\/[a-f0-9-]{36}/ nocase

    condition:
        $oastify_url or $webhook_url
}