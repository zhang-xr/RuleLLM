rule Discord_CDN_File_Download {
    meta:
        author = "RuleLLM"
        description = "Detects file downloads from Discord CDN URLs in Python scripts"
        confidence = 85
        severity = 75

    strings:
        $discord_cdn = "cdn.discordapp.com/attachments/"
        $curl_cmd = "curl.exe"
        $powershell_cmd = "powershell"

    condition:
        $discord_cdn and 
        (1 of ($curl_cmd, $powershell_cmd))
}