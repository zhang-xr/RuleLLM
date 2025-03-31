rule Malicious_Python_Setup_Base64_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts containing base64-encoded malicious payloads in install commands"
        confidence = "95"
        severity = "90"
    
    strings:
        $install_class = "class InstallCommand(install):"
        $base64_exec = /exec\(__import__\('base64'\)\.b64decode\([\"'][a-zA-Z0-9+\/]+={0,2}[\"']\)\)/
        $suspicious_methods = /(os\.mkdir|subprocess\.run|open\(.*,\s*[\"']w[\"']\))/
        $windows_path = /C:\\Users\\[^\\]+\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\System86/
    
    condition:
        all of them
}