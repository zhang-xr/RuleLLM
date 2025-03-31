rule Discord_CDN_Download {
    meta:
        author = "RuleLLM"
        description = "Detects downloads from Discord CDN URLs in Python scripts"
        confidence = 80
        severity = 70

    strings:
        $discord_cdn_url = /https:\/\/cdn\.discordapp\.com\/attachments\/\d+\/\d+\/[^\s]+/
        $curl_download = "curl.exe -L"
        $powershell_download = "Invoke-WebRequest"

    condition:
        $discord_cdn_url and
        any of ($curl_download, $powershell_download)
}