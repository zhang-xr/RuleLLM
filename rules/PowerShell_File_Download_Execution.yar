rule PowerShell_File_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands for file download and execution in Python scripts"
        confidence = 95
        severity = 90
    strings:
        $download = /curl\.exe -L [^\"]+\.exe -o/
        $execute = /Start-Process .*\.exe.*-NoNewWindow -Wait/
        $powershell = "powershell"
        $subprocess = "subprocess.run"
    condition:
        ($download and $powershell) or ($execute and $powershell) or $subprocess
}