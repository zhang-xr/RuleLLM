rule Remote_File_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects remote file download and execution patterns in Python scripts."
        confidence = 85
        severity = 90
    strings:
        $invoke_webrequest = /Invoke-WebRequest\s+-Uri\s+['"][^'"]+['"]/
        $start_process = /Start-Process\s+['"][^'"]+['"]/
        $powershell = "powershell -Command"
    condition:
        all of them
}