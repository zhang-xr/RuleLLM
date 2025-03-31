rule Python_CustomInstall_Override {
    meta:
        author = "RuleLLM"
        description = "Detects custom installation command overrides in Python packages"
        confidence = 85
        severity = 80
    strings:
        $cmdclass = "cmdclass"
        $custom_install = "CustomInstallCommand"
        $install_override = "'install': CustomInstallCommand"
    condition:
        all of them and 
        filesize < 10KB
}