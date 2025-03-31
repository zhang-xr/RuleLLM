rule PotentialReverseShell_SetupPy {
    meta:
        author = "RuleLLM"
        description = "Detects potential reverse shell patterns in setup.py"
        confidence = 85
        severity = 90

    strings:
        $reverse_shell = "bash -i >& /dev/"
        $egg_info = "class RunEggInfoCommand(egg_info):"
        $setup = "setup("

    condition:
        all of ($reverse_shell, $egg_info, $setup)
}