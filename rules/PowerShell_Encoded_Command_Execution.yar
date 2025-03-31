rule PowerShell_Encoded_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell encoded command execution patterns"
        confidence = 95
        severity = 90

    strings:
        $encoded_cmd = /-EncodedCommand\s+[A-Za-z0-9+\/]+={0,2}/
        $powershell = "powershell" nocase
        $hidden = "-WindowStyle Hidden" nocase
        $no_window = "CREATE_NO_WINDOW" nocase

    condition:
        all of them
}