rule Malicious_Download_And_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used to download and execute an unknown executable"
        confidence = 90
        severity = 85
    strings:
        $download_cmd = /curl\.exe -L [^\"]+ -o/
        $execute_cmd = /Start-Process .*\.exe.*-NoNewWindow -Wait/
        $powershell = "powershell"
        $subprocess = "subprocess.run"
    condition:
        all of them and filesize < 10KB
}