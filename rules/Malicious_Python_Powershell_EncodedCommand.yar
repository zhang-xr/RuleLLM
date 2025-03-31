rule Malicious_Python_Powershell_EncodedCommand {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using subprocess.Popen with PowerShell encoded commands"
        confidence = 95
        severity = 90
    
    strings:
        $powershell_cmd = "powershell -EncodedCommand"
        $subprocess_popen = "subprocess.Popen"
        $create_no_window = "CREATE_NO_WINDOW"
    
    condition:
        all of them and filesize < 10KB
}