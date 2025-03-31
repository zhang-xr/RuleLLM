rule Malicious_Download_Execute_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell-based download and execute patterns commonly used in malware"
        confidence = 90
        severity = 85
    strings:
        $download_cmd = /curl\.exe\s+-L\s+https?:\/\/[^\s]+\s+-o\s+"[^"]+"/
        $powershell_cmd = "powershell"
        $start_process = "Start-Process"
        $no_new_window = "-NoNewWindow"
        $wait_flag = "-Wait"
    condition:
        all of them and 
        filesize < 2KB
}