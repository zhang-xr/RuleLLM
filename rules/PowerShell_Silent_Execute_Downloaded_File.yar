rule PowerShell_Silent_Execute_Downloaded_File {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to silently execute a downloaded file."
        confidence = 85
        severity = 80

    strings:
        $execute_cmd = /Start\-Process\s+"[^"]+"\s+-NoNewWindow\s+-Wait/
        $powershell = "powershell" nocase

    condition:
        $execute_cmd and $powershell
}