rule Python_Custom_Install_Backdoor {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious custom install commands in Python setup scripts"
        confidence = 85
        severity = 75
    strings:
        $install_class = "class PreInstallCommand(install)"
        $subprocess_call = "subprocess.check_call"
        $setup_cmdclass = "'install': PreInstallCommand"
    condition:
        all of them and 
        not filesize < 1KB and 
        not $install_class in (0..filesize-100)
}