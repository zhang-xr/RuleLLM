rule Python_MaliciousSetupCommands {
    meta:
        author = "RuleLLM"
        description = "Detects malicious custom setup commands in Python packages"
        confidence = 80
        severity = 85

    strings:
        $custom_install = "class CustomInstallCommand(install):"
        $custom_develop = "class CustomDevelopCommand(develop):"
        $custom_egg_info = "class CustomEggInfoCommand(egg_info):"
        $custom_command_call = "custom_command()"

    condition:
        ($custom_install or $custom_develop or $custom_egg_info) and $custom_command_call
}