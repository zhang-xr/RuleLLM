rule PowerShell_curl_Download_External_File {
    meta:
        author = "RuleLLM"
        description = "Detects the use of curl.exe in PowerShell to download a file from an external URL."
        confidence = 85
        severity = 80

    strings:
        $curl_cmd = /curl\.exe\s+-L\s+https?:\/\/[^\s]+\s+-o\s+"[^"]+"/
        $powershell = "powershell" nocase

    condition:
        $curl_cmd and $powershell
}