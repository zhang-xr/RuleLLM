rule Malicious_PowerShell_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to download and execute malicious files"
        confidence = "90"
        severity = "85"
    
    strings:
        $ps_command = "powershell -WindowStyle Hidden -EncodedCommand"
        $invoke_webrequest = "Invoke-WebRequest"
        $invoke_expression = "Invoke-Expression"
        $outfile = "-OutFile"
        $encoded_cmd = /SQBuAHQAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0/
    
    condition:
        any of ($ps_command, $invoke_webrequest, $invoke_expression, $outfile) and $encoded_cmd
}