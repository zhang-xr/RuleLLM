rule Malicious_PowerShell_EncodedCommand {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious PowerShell commands with encoded parameters often used in malware"
        confidence = 90
        severity = 85
    strings:
        $ps_encoded = "-EncodedCommand"
        $hidden_window = "-WindowStyle Hidden"
        $invoke_web = "Invoke-WebRequest"
        $invoke_expr = "Invoke-Expression"
        $github_url = "github.com" nocase
        $powershell = "powershell" nocase
    condition:
        all of ($ps_encoded, $hidden_window) and 
        (any of ($invoke_web, $invoke_expr)) and 
        $powershell and
        $github_url
}