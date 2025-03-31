rule Suspicious_Python_Powershell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts executing PowerShell commands with suspicious parameters"
        confidence = 90
        severity = 85
        reference = "Analyzed code segment"
    
    strings:
        $powershell = "powershell"
        $command_flag = "-Command"
        $subprocess = "subprocess.run("
        $no_window = "-NoNewWindow"
        $wait_flag = "-Wait"
    
    condition:
        $subprocess and 
        $powershell and 
        $command_flag and 
        ($no_window or $wait_flag)
}