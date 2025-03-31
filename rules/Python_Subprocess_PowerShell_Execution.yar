rule Python_Subprocess_PowerShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using subprocess to run PowerShell commands"
        confidence = 85
        severity = 80
    strings:
        $subprocess = "subprocess.run" wide ascii
        $powershell_cmd = /\["powershell",\s+"-Command",\s+"[^"]+\.exe"\]/
        $download_execute1 = "curl.exe" wide ascii
        $download_execute2 = "Start-Process" wide ascii
    condition:
        $subprocess and $powershell_cmd and ($download_execute1 or $download_execute2)
}