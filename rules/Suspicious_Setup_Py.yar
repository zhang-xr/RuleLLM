rule Suspicious_Setup_Py {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious patterns in Python setup.py files, including custom install commands and external dependencies"
        confidence = "80"
        severity = "70"

    strings:
        $setup_requires = "setup_requires"
        $install_requires = "install_requires"
        $cmdclass = "cmdclass"
        $custom_install = "CustomInstallCommand"

    condition:
        // Match suspicious setup.py patterns
        any of ($setup_requires, $install_requires) and
        all of ($cmdclass, $custom_install)
}