rule Python_Malicious_Setuptools_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setuptools installation commands that execute code during package installation."
        confidence = 95
        severity = 90

    strings:
        $class_def = "class CustomInstallCommand(install):"
        $install_override = "def run(self):"
        $datetime_check = /datetime\.datetime\([^\)]+\)/
        $cmdclass = "cmdclass={'install': CustomInstallCommand}"

    condition:
        all of them
}