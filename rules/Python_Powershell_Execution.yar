rule Python_Powershell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell commands used for process execution in Python scripts"
        confidence = 90
        severity = 85
    strings:
        $powershell_cmd = "powershell -Command"
        $start_process = "Start-Process"
        $file_execution = /Start-Process\s+'[^']+'/
    condition:
        all of them and 
        filesize < 10KB
}