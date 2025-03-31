rule Malicious_Powershell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious PowerShell command execution hidden in a Python setup script."
    strings:
        $ps_command = "powershell"
    condition:
        $ps_command
}