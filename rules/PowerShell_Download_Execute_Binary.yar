rule PowerShell_Download_Execute_Binary {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands downloading and executing a binary file"
        confidence = 90
        severity = 85
    strings:
        $curl_cmd = /curl\.exe\s+-L\s+[^\s]+\s+-o\s+"[^"]+\.exe"/
        $start_process = /Start-Process\s+"[^"]+\.exe"\s+(-NoNewWindow\s+|-Wait\s+){2}/
        $powershell = "powershell" wide ascii
    condition:
        all of them
}