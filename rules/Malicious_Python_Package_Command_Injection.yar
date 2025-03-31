rule Malicious_Python_Package_Command_Injection {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages executing shell commands during installation"
        confidence = 85
        severity = 90
    strings:
        $os_system = "os.system("
        $custom_command = "custom_command()"
        $cmdclass = "cmdclass={"
    condition:
        $os_system and $custom_command and $cmdclass
}