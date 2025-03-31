rule Cross_Platform_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects cross-platform execution patterns in Python code"
        confidence = 80
        severity = 85
    strings:
        $linux_check = "'linux' in operating_system"
        $windows_check = "'windows' in operating_system"
        $darwin_check = "'darwin' in operating_system"
        $platform_check = "platform.system().lower()"
    condition:
        2 of ($linux_check, $windows_check, $darwin_check) and 
        $platform_check
}