rule Python_PowerShell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that use subprocess.run to execute PowerShell commands."
        confidence = 85
        severity = 80

    strings:
        $subprocess = "subprocess.run"
        $powershell = "powershell" nocase
        $command = /-Command\s+["']/

    condition:
        all of them
}