rule Python_Powershell_FileDownload {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used for file downloads in Python scripts"
        confidence = 90
        severity = 85
    strings:
        $powershell_cmd = "powershell -Command"
        $invoke_webrequest = "Invoke-WebRequest"
        $outfile = "-OutFile"
    condition:
        all of them and 
        filesize < 10KB
}