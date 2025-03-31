rule Python_SuspiciousSetupConfiguration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup configurations in Python setup scripts"
        confidence = "85"
        severity = "80"
    
    strings:
        $cmdclass_setup = "cmdclass={'install': CustomInstallCommand}"
        $custom_install = "class CustomInstallCommand"
    
    condition:
        all of ($cmdclass_setup, $custom_install)
}