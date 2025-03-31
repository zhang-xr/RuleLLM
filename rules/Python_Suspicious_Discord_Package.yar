rule Python_Suspicious_Discord_Package {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with suspicious Discord-related distribution patterns"
        confidence = 85
        severity = 75
        reference = "Potential malicious package distribution via Discord"
    
    strings:
        $discord_invite = /discord\.gg\/[\w-]{6,}/ wide
        $suspicious_email = /https?[^\s@]+@[^\s@]+\.[^\s@]+/ wide
        $typosquatting = /[a-z]{6,8}im/ nocase
    
    condition:
        (2 of them) and 
        filesize < 5KB
}