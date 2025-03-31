rule Malicious_SetupPy_Commands {
    meta:
        author = "RuleLLM"
        description = "Detects malicious modifications to setup.py commands"
        confidence = 90
        severity = 85

    strings:
        $custom_command = "custom_command"
        $install_class = /class\s+\w+\(install\):\s+def\s+run\(self\):/
        $develop_class = /class\s+\w+\(develop\):\s+def\s+run\(self\):/
        $cmdclass = "cmdclass"

    condition:
        $cmdclass and ($install_class or $develop_class) and $custom_command
}