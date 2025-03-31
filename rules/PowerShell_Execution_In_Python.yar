rule PowerShell_Execution_In_Python {
    meta:
        author = "RuleLLM"
        description = "Detects PowerShell execution in Python scripts."
        confidence = 75
        severity = 65

    strings:
        $powershell_command = "powershell -Command" nocase
        $subprocess_run = "subprocess.run"

    condition:
        $powershell_command and $subprocess_run
}