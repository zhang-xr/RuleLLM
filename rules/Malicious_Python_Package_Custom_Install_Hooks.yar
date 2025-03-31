rule Malicious_Python_Package_Custom_Install_Hooks {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages overriding setuptools commands for malicious purposes"
        confidence = 80
        severity = 85
    strings:
        $custom_install = "class CustomInstallCommand(install):"
        $custom_develop = "class CustomDevelopCommand(develop):"
        $custom_egg_info = "class CustomEggInfoCommand(egg_info):"
    condition:
        any of ($custom_install, $custom_develop, $custom_egg_info)
}