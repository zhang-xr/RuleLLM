rule Malicious_Python_Typosquatting_Discord {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files with typosquatting patterns and suspicious Discord links"
        confidence = "90"
        severity = "80"
    
    strings:
        $package_name = "discrd"
        $misspelled_keyword = "pynalc"
        $discord_link = "https://discord.gg/" nocase
        $email_discord = /[a-zA-Z0-9._%+-]+@httpsdiscord\.gg[a-zA-Z0-9._%+-]+/
    
    condition:
        all of ($package_name, $misspelled_keyword) and
        any of ($discord_link, $email_discord)
}