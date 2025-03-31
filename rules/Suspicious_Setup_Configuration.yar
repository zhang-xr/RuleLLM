rule Suspicious_Setup_Configuration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py configuration for malicious package installation"
        confidence = 90
        severity = 85

    strings:
        $cmdclass = "cmdclass"
        $install = "install"
        $setup = "setup("
        $install_requires = "install_requires"
        $setup_requires = "setup_requires"

    condition:
        $cmdclass and $install and $setup and ($install_requires or $setup_requires)
}