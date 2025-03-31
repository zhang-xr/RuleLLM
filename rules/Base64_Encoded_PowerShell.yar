rule Base64_Encoded_PowerShell {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded PowerShell commands commonly used in malicious scripts"
        confidence = 85
        severity = 80

    strings:
        $base64_pattern = /[A-Za-z0-9+\/]{50,}={0,2}/
        $powershell = "powershell"
        $cmd_exe = "cmd.exe"
        $invoke_expression = "Invoke-Expression"
        $invoke_webrequest = "Invoke-WebRequest"

    condition:
        $base64_pattern and 
        (any of ($powershell, $cmd_exe, $invoke_expression, $invoke_webrequest))
}