rule Python_Arbitrary_Shell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects arbitrary shell command execution in Python scripts"
        confidence = 80
        severity = 85

    strings:
        $os_system = "os.system"
        $subprocess_call = "subprocess.call"
        $malicious_echo = "echo \"恶意代码执行成功\""

    condition:
        any of ($os_system, $subprocess_call) and
        $malicious_echo
}