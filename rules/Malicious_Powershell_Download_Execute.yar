rule Malicious_Powershell_Download_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to download and execute a file from a remote URL"
        confidence = 90
        severity = 95

    strings:
        $ps1 = "powershell -WindowStyle Hidden -EncodedCommand" ascii
        $download_url = "https://cdn.discordapp.com/attachments/" ascii
        $output_file = "~/WindowsCache.exe" ascii
        $creation_flags = "CREATE_NO_WINDOW" ascii

    condition:
        all of them
}