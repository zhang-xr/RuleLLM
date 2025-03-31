rule Malicious_Shell_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious shell command execution in Python scripts"
        confidence = 95
        severity = 90

    strings:
        $os_system = "os.system"
        $malicious_message = /恶意代码执行成功/

    condition:
        $os_system and
        $malicious_message
}