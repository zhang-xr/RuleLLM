rule python_suspicious_setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious patterns in Python package setup files"
        confidence = 80
        severity = 85

    strings:
        $cmdclass = "cmdclass = {" // Custom command class
        $install_requires = "install_requires" // Dependencies list
        $setup_call = "setup(" // Setup function call

    condition:
        all of ($cmdclass, $install_requires, $setup_call)
}