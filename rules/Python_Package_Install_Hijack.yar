rule Python_Package_Install_Hijack {
    meta:
        author = "RuleLLM"
        description = "Detects Python package installation hijacking patterns"
        confidence = 85
        severity = 75
    strings:
        $install_override = "class CustomInstallCommand(install)"
        $cmdclass = "cmdclass={'install': CustomInstallCommand,}"
        $system_cmd = /subprocess\.run\(\[[^\]]+\]/
    condition:
        all of ($install_override, $cmdclass) and 
        any of ($system_cmd)
}