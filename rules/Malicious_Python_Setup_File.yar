rule Malicious_Python_Setup_File {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup files with suspicious metadata"
        confidence = 80
        severity = 75
    
    strings:
        $setup_metadata = /setup\(\s*name\s*=\s*[^,]+,\s*packages\s*=\s*[^,]+,\s*version\s*=\s*[^,]+/
        $powershell_cmd = "powershell"
        $discord_cdn = "cdn.discordapp.com/attachments"
    
    condition:
        all of them and filesize < 10KB
}