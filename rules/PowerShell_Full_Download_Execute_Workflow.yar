rule PowerShell_Full_Download_Execute_Workflow {
    meta:
        author = "RuleLLM"
        description = "Detects the full workflow of downloading and executing a file using PowerShell."
        confidence = 95
        severity = 90

    strings:
        $download_cmd = /curl\.exe\s+-L\s+[^\s]+\s+-o\s+"[^"]+"/
        $execute_cmd = /Start\-Process\s+"[^"]+"\s+-NoNewWindow\s+-Wait/
        $powershell = "powershell" nocase

    condition:
        all of them and
        $download_cmd and $execute_cmd in (0..500)
}