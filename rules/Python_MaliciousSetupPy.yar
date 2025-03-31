rule Python_MaliciousSetupPy {
    meta:
        author = "RuleLLM"
        description = "Detects malicious modifications to setup.py that execute arbitrary commands"
        confidence = 85
        severity = 75

    strings:
        $custom_command = "def custom_command():"
        $os_system = "os.system"
        $cmdclass = "cmdclass"
        $install_class = /class\s+\w+\(install\):/
        $develop_class = /class\s+\w+\(develop\):/
        $egg_info_class = /class\s+\w+\(egg_info\):/

    condition:
        all of ($custom_command, $os_system, $cmdclass) and 
        any of ($install_class, $develop_class, $egg_info_class)
}