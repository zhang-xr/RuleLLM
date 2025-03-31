rule Discord_Payload_Delivery {
    meta:
        author = "RuleLLM"
        description = "Detects specific Discord CDN URL patterns used for malicious payload delivery"
        confidence = 100
        severity = 95
    
    strings:
        $discord_url = "https://cdn.discordapp.com/attachments/" nocase
        $exe_file = ".exe" nocase
        $requests_get = "requests.get"
    
    condition:
        all of ($discord_url, $exe_file, $requests_get)
}