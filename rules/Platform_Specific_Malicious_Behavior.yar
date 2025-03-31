rule Platform_Specific_Malicious_Behavior {
    meta:
        author = "RuleLLM"
        description = "Detects platform-specific malicious behavior, such as clearing the screen and checking the OS"
        confidence = 75
        severity = 65

    strings:
        $platform_check = "platform.system()"
        $clear_screen_linux = "print(\"\\033c\")"
        $clear_screen_windows = "os.system(\"cls\")"

    condition:
        any of them
}