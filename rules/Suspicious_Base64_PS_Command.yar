rule Suspicious_Base64_PS_Command {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded PowerShell commands in Python scripts"
        confidence = "85"
        severity = "80"
    
    strings:
        // Base64 encoded command pattern
        $b64 = /cABvAHcAZQByAHMAaABlAGwAbAAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAA=/ ascii wide
        
        // PowerShell indicators
        $ps1 = "powershell" ascii wide
        $ps2 = "-EncodedCommand" ascii wide
        
    condition:
        // Match if base64-encoded PowerShell command is detected
        $b64 and ($ps1 or $ps2)
}