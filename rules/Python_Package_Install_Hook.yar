rule Python_Package_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious package installation hooks in Python setup.py"
        confidence = 85
        severity = 80
        reference = "Custom PostInstallCommand class"
    
    strings:
        $install_hook1 = "cmdclass={'install': PostInstallCommand}" nocase wide ascii
        $install_hook2 = "class PostInstallCommand(install)" nocase wide ascii
        $setup = "setup(" nocase wide ascii
    
    condition:
        all of ($install_hook1, $setup) or 
        all of ($install_hook2, $setup)
}