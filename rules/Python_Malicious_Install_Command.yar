rule Python_Malicious_Install_Command {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package install commands"
        confidence = "90"
        severity = "85"
    
    strings:
        $install_class = "class CustomInstallCommand(install)"
        $cmdclass = "cmdclass={'install': CustomInstallCommand"
        $install_run = "install.run(self)"
        $setup = "setup("
        
    condition:
        all of them and 
        $install_run in (0..500)
}