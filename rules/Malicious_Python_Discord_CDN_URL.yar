rule Malicious_Python_Discord_CDN_URL {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts downloading files from Discord CDN URLs"
        confidence = 90
        severity = 85
    
    strings:
        $discord_cdn = "cdn.discordapp.com/attachments"
        $invoke_webrequest = "Invoke-WebRequest"
        $invoke_expression = "Invoke-Expression"
    
    condition:
        all of them and filesize < 10KB
}