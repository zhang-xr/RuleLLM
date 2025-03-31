rule Malicious_Python_Hidden_Powershell {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts executing PowerShell with hidden windows"
        confidence = 85
        severity = 80
    
    strings:
        $powershell_cmd = "powershell"
        $hidden_window = "-WindowStyle Hidden"
        $create_no_window = "CREATE_NO_WINDOW"
    
    condition:
        all of them and filesize < 10KB
}