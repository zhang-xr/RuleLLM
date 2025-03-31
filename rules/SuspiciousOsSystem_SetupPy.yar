rule SuspiciousOsSystem_SetupPy {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious os.system usage in setup.py"
        confidence = 80
        severity = 70

    strings:
        $os_system = "os.system(" ascii wide
        $egg_info = "class RunEggInfoCommand(egg_info):"
        $setup = "setup("

    condition:
        all of ($os_system, $egg_info, $setup)
}