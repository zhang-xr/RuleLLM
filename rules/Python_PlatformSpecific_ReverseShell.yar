rule Python_PlatformSpecific_ReverseShell {
    meta:
        author = "RuleLLM"
        description = "Detects platform-specific reverse shell behavior in Python"
        confidence = 80
        severity = 85

    strings:
        $platform_check = "sys.platform"
        $windows_cmd = /cmd.*\/K.*cd/
        $linux_bash = "/bin/bash"
        $os_dup2 = "os.dup2"

    condition:
        $platform_check and
        (1 of ($windows_cmd, $linux_bash)) and
        $os_dup2
}