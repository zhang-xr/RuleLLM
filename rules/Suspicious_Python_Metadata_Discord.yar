rule Suspicious_Python_Metadata_Discord {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files with suspicious metadata containing Discord links"
        confidence = "85"
        severity = "75"
    
    strings:
        $discord_link = "https://discord.gg/" nocase
        $email_discord = /[a-zA-Z0-9._%+-]+@httpsdiscord\.gg[a-zA-Z0-9._%+-]+/
        $random_author = /[a-zA-Z0-9]{4,10} [A-Z][a-z]+/
    
    condition:
        any of ($discord_link, $email_discord) and
        $random_author
}