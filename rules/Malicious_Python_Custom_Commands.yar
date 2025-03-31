rule Malicious_Python_Custom_Commands {
    meta:
        author = "RuleLLM"
        description = "Detects custom command overrides in setup.py for malicious execution"
        confidence = 85
        severity = 80

    strings:
        $custom_install = "class CustomInstallCommand(install)"
        $custom_develop = "class CustomDevelopCommand(develop)"
        $custom_egg_info = "class CustomEggInfoCommand(egg_info)"
        $cmdclass = "cmdclass={"

    condition:
        ($custom_install or $custom_develop or $custom_egg_info) and $cmdclass
}