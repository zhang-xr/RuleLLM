rule Malicious_Python_Setup_PS_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts that use PowerShell to download and execute files"
        confidence = "95"
        severity = "90"
    
    strings:
        // PowerShell execution patterns
        $ps1 = "subprocess.Popen('powershell" ascii wide
        $ps2 = "-WindowStyle Hidden" ascii wide
        $ps3 = "-EncodedCommand" ascii wide
        
        // Common PowerShell download/execute commands
        $ps4 = "Invoke-WebRequest" ascii wide
        $ps5 = "Invoke-Expression" ascii wide
        
        // Suspicious domain pattern
        $domain = /esqueles[a-z]{0,4}\.000webhostapp\.com/ ascii wide
        
        // Base64 encoded command indicator
        $b64 = /[A-Za-z0-9+\/]{50,}={0,2}/ ascii wide
        
    condition:
        // Match if PowerShell execution is detected with encoded command
        (2 of ($ps*)) and
        ($b64 or $domain) and
        filesize < 10KB
}