rule Python_Powershell_EncodedCommand_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using encoded PowerShell commands to download and execute files"
        confidence = 95
        severity = 90
    strings:
        $ps_invoke = "subprocess.Popen('powershell" nocase
        $encoded_cmd = "-EncodedCommand" nocase
        $web_request = "Invoke-WebRequest" nocase
        $hidden_window = "-WindowStyle Hidden" nocase
        $outfile = "-OutFile" nocase
    condition:
        filesize < 10KB and
        all of them
}