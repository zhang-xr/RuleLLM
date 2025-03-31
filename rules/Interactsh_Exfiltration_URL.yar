rule Interactsh_Exfiltration_URL {
    meta:
        author = "RuleLLM"
        description = "Detects URLs associated with Interactsh used for exfiltration"
        confidence = 95
        severity = 85

    strings:
        // Interactsh URL pattern
        $interactsh_url = /https?:\/\/[a-z0-9]+\.oastify\.com/ nocase

    condition:
        // Match if the URL pattern is found
        $interactsh_url
}