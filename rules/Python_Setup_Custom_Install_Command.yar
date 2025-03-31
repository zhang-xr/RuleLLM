rule Python_Setup_Custom_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects custom install commands in Python setup scripts, which could be used for malicious purposes"
        confidence = 85
        severity = 80

    strings:
        $cmdclass_config = "cmdclass={'install':"
        $custom_install_class = "class CustomInstallCommand("

    condition:
        $cmdclass_config or $custom_install_class
}