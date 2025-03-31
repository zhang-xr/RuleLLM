rule Suspicious_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup with command hooks"
        confidence = "85"
        severity = "80"
    
    strings:
        $setup = "setup(name="
        $cmdclass = "cmdclass={"
        $install_hook = "'install': CustomInstallCommand"
        $develop_hook = "'develop': CustomDevelopCommand"
        $egg_hook = "'egg_info': CustomEggInfoCommand"
        $suspicious_desc = /research\s+survey|test\s+purposes|victim's\s+machines/i
    
    condition:
        $setup and $cmdclass and
        ($install_hook or $develop_hook or $egg_hook) and
        $suspicious_desc
}