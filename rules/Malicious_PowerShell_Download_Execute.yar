rule Malicious_PowerShell_Download_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to download and execute a file from a remote URL"
        confidence = 90
        severity = 85

    strings:
        $powershell_cmd = "powershell -WindowStyle Hidden -EncodedCommand"
        $base64_pattern = /SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0/
        $invoke_webrequest = "Invoke-WebRequest"
        $outfile = "-OutFile"
        $invoke_expression = "Invoke-Expression"

    condition:
        any of ($powershell_cmd, $base64_pattern) and 
        (any of ($invoke_webrequest, $outfile, $invoke_expression))
}