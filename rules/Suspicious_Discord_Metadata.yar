rule Suspicious_Discord_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Discord-related metadata in Python packages"
        confidence = 85
        severity = 75

    strings:
        $discord_url = "https://discord.gg/"
        $email_discord = /httpsdiscord\.gg\S+@/
        $suspicious_keywords = /(discord|typosquatting|voice|mp3)/

    condition:
        2 of ($discord_url, $email_discord) and 
        #suspicious_keywords >= 2
}