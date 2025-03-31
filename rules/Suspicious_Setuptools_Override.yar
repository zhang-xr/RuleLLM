rule Suspicious_Setuptools_Override {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious overrides of setuptools installation commands"
        confidence = 85
        severity = 75
    strings:
        $cmd_override1 = "cmdclass={'install':"
        $cmd_override2 = "cmdclass={'develop':"
        $cmd_override3 = "cmdclass={'egg_info':"
        $custom_run = "def run(self):"
    condition:
        (2 of ($cmd_override*)) and $custom_run
}