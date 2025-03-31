rule Malicious_Encoded_PowerShell_InvokeWebRequest {
    meta:
        author = "RuleLLM"
        description = "Detects encoded PowerShell commands using Invoke-WebRequest to download and execute files"
        confidence = 90
        severity = 80

    strings:
        $encoded_cmd1 = "SQBuAHYAbwBrAGUALQBXAGUAYgBSAGUAcQB1AGUAcwB0" // Base64 for "Invoke-WebRequest"
        $encoded_cmd2 = "SQBuAHYAbwBrAGUALQBFAHgAcAByAGUAcwBzAGkAbwBu" // Base64 for "Invoke-Expression"
        $powershell = "powershell" nocase
        $encoded_command = "-EncodedCommand" nocase

    condition:
        all of them and 
        filesize < 10KB // Limits to small scripts
}