rule Python_Network_Shell {
    meta:
        author = "RuleLLM"
        description = "Detects network shell commands in Python code"
        confidence = 98
        severity = 95

    strings:
        $tcp_shell = /(bash|sh).*>&\s*\/dev\/tcp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}/ nocase
        $udp_shell = /(bash|sh).*>&\s*\/dev\/udp\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/\d{1,5}/ nocase

    condition:
        any of ($tcp_shell, $udp_shell)
}