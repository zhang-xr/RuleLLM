rule PowerShell_Download_Execute_External_File {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to download and execute an external executable file."
        confidence = 90
        severity = 85

    strings:
        $download_cmd = /curl\.exe\s+-L\s+[^\s]+\s+-o\s+"[^"]+"/
        $execute_cmd = /Start\-Process\s+"[^"]+"\s+-NoNewWindow\s+-Wait/
        $powershell = "powershell" nocase

    condition:
        all of them and
        $download_cmd and $execute_cmd in (0..1000)
}