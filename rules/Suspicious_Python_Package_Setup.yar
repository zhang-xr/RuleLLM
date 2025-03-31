rule Suspicious_Python_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup scripts with custom commands."
        confidence = 85
        severity = 90
    strings:
        $custom_command = "def custom_command():"
        $os_system = "os.system"
        $cmdclass = "cmdclass={"
        $install_hook = /(install|develop|egg_info)\s*:\s*Custom\w+Command/
    condition:
        all of ($custom_command, $os_system, $cmdclass) and any of ($install_hook)
}