rule Python_Typosquatting_aiohttp {
    meta:
        author = "RuleLLM"
        description = "Detects typosquatting attempts targeting aiohttp package"
        confidence = 95
        severity = 80
    strings:
        $pkg_name = "aiohtttps" nocase
        $author = "m6xw Dingle" nocase
        $discord_email = /httpsdiscord\.gg[a-zA-Z0-9]{4,}@/
        $discord_url = "https://discord.gg/" nocase
        $typosquatting_kw = "typosquatting" nocase
    condition:
        all of them
}