rule Malicious_Python_Package_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation command overriding."
        confidence = 85
        severity = 90

    strings:
        $install_command = "class InstallCommand(install)"
        $cmdclass = "cmdclass={'install': InstallCommand}"

    condition:
        all of them and filesize < 10KB
}