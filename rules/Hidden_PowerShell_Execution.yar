rule Hidden_PowerShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects hidden PowerShell execution with CREATE_NO_WINDOW flag."
        confidence = 85
        severity = 75
    
    strings:
        $create_no_window = "CREATE_NO_WINDOW"
        $powershell = "powershell"
        $hidden_execution = "-WindowStyle Hidden"
    
    condition:
        all of them
}