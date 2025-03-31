rule Platform_Specific_Malicious_Behavior_2 {
    meta:
        author = "RuleLLM"
        description = "Detects platform-specific malicious behavior, including screen clearing and file checks."
        confidence = 80
        severity = 75

    strings:
        $platform_system = "platform.system()"
        $os_system_cls = "os.system(\"cls\")"
        $os_system_clear = "os.system(\"\\033c\")"
        $path_is_file = "path.is_file()"

    condition:
        any of ($os_system_cls, $os_system_clear) and all of ($platform_system, $path_is_file)
}