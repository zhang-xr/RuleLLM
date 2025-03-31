rule Hidden_PowerShell_Execution_Python {
    meta:
        author = "RuleLLM"
        description = "Detects hidden PowerShell execution within Python scripts"
        confidence = 95
        severity = 90

    strings:
        $powershell = "powershell" nocase
        $hidden_window = "-WindowStyle Hidden" nocase
        $create_no_window = "CREATE_NO_WINDOW" nocase
        $subprocess = "subprocess.Popen" nocase

    condition:
        all of them
}