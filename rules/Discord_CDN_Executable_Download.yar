rule Discord_CDN_Executable_Download {
    meta:
        author = "RuleLLM"
        description = "Detects downloading an executable from Discord's CDN"
        confidence = 95
        severity = 100
    strings:
        $discord_cdn_url = /https:\/\/cdn\.discordapp\.com\/[^\s]+\.exe/
    condition:
        $discord_cdn_url
}