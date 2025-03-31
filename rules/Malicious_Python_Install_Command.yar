rule Malicious_Python_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with custom install commands that execute shell commands"
        confidence = 90
        severity = 80

    strings:
        $cmdclass = "cmdclass"
        $os_popen = "os.popen"
        $install_class = "class CustomInstallCommand(install):"
        $install_run = "def run(self):"

    condition:
        all of ($cmdclass, $os_popen) and 
        (1 of ($install_class, $install_run))
}