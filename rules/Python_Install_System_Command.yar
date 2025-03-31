rule Python_Install_System_Command {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that executes system commands during package installation."
        confidence = 80
        severity = 70

    strings:
        $subprocess_run = /subprocess\.run\(\[.*?\]\, capture_output=True\, text=True\)/
        $whoami = /"whoami"/
        $install_class = "class CustomInstallCommand(install):"

    condition:
        $install_class and $subprocess_run and $whoami
}