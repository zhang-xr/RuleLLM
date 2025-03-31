rule Malicious_Command_Execution_osSystem {
    meta:
        author = "RuleLLM"
        description = "Detects the use of os.system to execute shell commands, often used in malicious scripts."
        confidence = "90"
        severity = "85"

    strings:
        $os_system = "os.system"
        $shell_command = /"[^"]+"/

    condition:
        $os_system and $shell_command
}