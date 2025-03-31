rule Python_SuspiciousSetup_CmdClass {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious cmdclass configuration in setup.py"
        confidence = 85
        severity = 75
    strings:
        $cmdclass = /cmdclass\s*=\s*{/
        $custom_command = /'\w+'\s*:\s*\w+/
        $setup_call = /setuptools\.setup\(/
    condition:
        all of them and
        filesize < 10KB
}