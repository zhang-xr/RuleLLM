rule Typosquatting_Package_Indicators {
    meta:
        author = "RuleLLM"
        description = "Detects typosquatting attempts in Python packages"
        confidence = 90
        severity = 80

    strings:
        $package_name1 = "aiohtttps"
        $package_name2 = "selenim"
        $author = "m6xw Dingle"
        $discord_url = "https://discord.gg/"
        $email_discord = /httpsdiscord\.gg\S+@/
        $typosquatting_keyword = "typosquatting"

    condition:
        (($package_name1 or $package_name2) and $author) or
        (($discord_url or $email_discord) and $typosquatting_keyword)
}