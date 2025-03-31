rule Malicious_Python_Powershell_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using hidden PowerShell to download and execute files"
        confidence = 95
        severity = 90
        
    strings:
        $powershell = "powershell -WindowStyle Hidden" nocase
        $encoded_cmd = /-EncodedCommand\s+[A-Za-z0-9+\/]{50,}={0,2}/
        $creation_flags = "CREATE_NO_WINDOW"
        $invoke_web = "Invoke-WebRequest" nocase
        $invoke_exp = "Invoke-Expression" nocase
        $hidden_window = "-WindowStyle Hidden" nocase
        
    condition:
        all of ($powershell, $encoded_cmd) or 
        (2 of ($powershell, $creation_flags, $hidden_window) and 1 of ($invoke_web, $invoke_exp))
}