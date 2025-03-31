rule Python_Shell_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code executing arbitrary shell commands during installation"
        confidence = 85
        severity = 75

    strings:
        $os_popen = "os.popen"
        $os_system = "os.system"
        $install_class = "class CustomInstallCommand(install):"
        $install_run = "def run(self):"

    condition:
        (any of ($os_popen, $os_system)) and 
        (1 of ($install_class, $install_run))
}