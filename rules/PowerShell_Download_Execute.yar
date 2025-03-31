rule PowerShell_Download_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell download and execute patterns using curl.exe and Start-Process"
        confidence = 90
        severity = 85
    strings:
        $ps_download = /curl\.exe\s+-L\s+[^\s]+\s+-o\s+"[^"]+"/
        $ps_execute = /Start-Process\s+"[^"]+"\s+-NoNewWindow\s+-Wait/
        $subprocess = "subprocess.run"
        $powershell = "powershell"
    condition:
        all of them and 
        #ps_download < 50 and 
        #ps_execute < 50
}