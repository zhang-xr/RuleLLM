rule Malicious_Python_Setup_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with reverse shell commands in custom install classes"
        confidence = 95
        severity = 90

    strings:
        $install_class = "class CustomInstallCommand(install):"
        $os_system = "os.system"
        $reverse_shell = /bash -c 'bash -i >& \/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5} <&1'/

    condition:
        $install_class and $os_system and $reverse_shell
}