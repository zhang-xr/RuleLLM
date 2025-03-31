rule Malicious_Subprocess_Powershell {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of subprocess.Popen to execute PowerShell commands"
        confidence = 85
        severity = 80
    strings:
        $subprocess = "subprocess.Popen"
        $powershell = "powershell" nocase
        $hidden_window = "-WindowStyle Hidden"
        $create_no_window = "CREATE_NO_WINDOW"
    condition:
        all of ($subprocess, $powershell) and 
        (any of ($hidden_window, $create_no_window))
}