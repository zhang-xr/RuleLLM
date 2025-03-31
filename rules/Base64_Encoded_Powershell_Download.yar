rule Base64_Encoded_Powershell_Download {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded PowerShell download commands"
        confidence = "95"
        severity = "90"
    strings:
        $base64_header = "SQBuAHYAbwBrAGUA"
        $powershell_cmd = "powershell -EncodedCommand"
        $web_request = /Invoke[-_]WebRequest/i
    condition:
        $base64_header and $powershell_cmd and $web_request
}