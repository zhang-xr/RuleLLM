rule Discord_CDN_Malicious_URL {
    meta:
        author = "RuleLLM"
        description = "Detects malicious URLs hosted on Discord CDN"
        confidence = 80
        severity = 85

    strings:
        $discord_cdn = "https://cdn.discordapp.com/attachments/" ascii

    condition:
        $discord_cdn
}