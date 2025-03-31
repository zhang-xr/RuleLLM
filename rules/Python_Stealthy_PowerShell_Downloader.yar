rule Python_Stealthy_PowerShell_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using hidden PowerShell to download and execute files"
        confidence = 95
        severity = 90
        
    strings:
        $ps1 = "powershell -WindowStyle Hidden -EncodedCommand"
        $subprocess = "subprocess.Popen"
        $create_no_window = "CREATE_NO_WINDOW"
        $invoke_web = "Invoke-WebRequest" nocase
        $outfile = "-OutFile" nocase
        $invoke_expr = "Invoke-Expression" nocase
        
    condition:
        all of them and filesize < 10KB
}