rule Malicious_Package_Combined_Indicators {
    meta:
        author = "RuleLLM"
        description = "Detects multiple indicators of potentially malicious Python packages"
        confidence = 95
        severity = 90

    strings:
        $package_name1 = "aiohtttps"
        $package_name2 = "selenim"
        $author = "m6xw Dingle"
        $discord_url = "https://discord.gg/"
        $email_discord = /httpsdiscord\.gg\S+@/
        $typosquatting_keyword = "typosquatting"
        $suspicious_keywords = /(discord|typosquatting|voice|mp3)/

    condition:
        (($package_name1 or $package_name2) and $author) or
        (($discord_url or $email_discord) and $typosquatting_keyword) or
        (2 of ($discord_url, $email_discord) and #suspicious_keywords >= 2)
}