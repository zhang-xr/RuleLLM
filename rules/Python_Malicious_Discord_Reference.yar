rule Python_Malicious_Discord_Reference {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python packages using Discord references"
        confidence = 85
        severity = 70
    strings:
        $discord_in_email = /@.*discord\.gg/ nocase
        $discord_in_url = "https://discord.gg/" nocase
        $suspicious_keywords = "typosquatting" nocase
    condition:
        ($discord_in_email or $discord_in_url) and $suspicious_keywords
}