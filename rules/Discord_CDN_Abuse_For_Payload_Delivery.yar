rule Discord_CDN_Abuse_For_Payload_Delivery {
    meta:
        author = "RuleLLM"
        description = "Detects abuse of Discord CDN for delivering malicious payloads"
        confidence = 90
        severity = 85

    strings:
        $discord_cdn_url = /https?:\/\/cdn\.discordapp\.com\/attachments\/[^\s]+\.exe/ ascii
        $requests_get = "requests.get(" ascii
        $tempfile_write = "tmp_file.write(" ascii

    condition:
        $discord_cdn_url and 
        all of ($requests_get, $tempfile_write)
}