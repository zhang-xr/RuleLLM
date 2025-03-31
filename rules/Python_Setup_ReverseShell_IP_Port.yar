rule Python_Setup_ReverseShell_IP_Port {
    meta:
        author = "RuleLLM"
        description = "Detects reverse shell commands in Python setup scripts with specific IP and port patterns"
        confidence = 98
        severity = 95

    strings:
        $reverse_shell = /bash -c 'bash -i >& \/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5} <&1'/

    condition:
        $reverse_shell
}