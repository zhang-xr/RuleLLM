rule Python_DiscordCDN_Downloader_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code downloading and executing executables from Discord CDN"
        confidence = 90
        severity = 80
    strings:
        $discord_cdn = "cdn.discordapp.com/attachments/" ascii wide
        $requests_get = "requests.get" ascii wide
        $write_binary = "wb).write(response.content)" ascii wide
        $system_exec = "os.system" ascii wide
        $start_cmd = /start\s+\w+\.exe/i ascii wide
    condition:
        all of them and 
        filesize < 10KB
}