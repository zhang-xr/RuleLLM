rule Suspicious_OS_System_Shell_Command {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of os.system() to execute shell commands, often used in malicious scripts."
        confidence = 90
        severity = 80

    strings:
        $os_system = "os.system"
        $shell_command = /os\.system\([\'\"][a-zA-Z0-9_\-\.\s]+[\'\"]\)/
        $id_command = "id"

    condition:
        all of ($os_system, $shell_command) and $id_command
}