rule Malicious_Socket_Connection_Combined {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded IP and port combination used for malicious socket connections."
        confidence = 90
        severity = 85
    strings:
        $ip = "134.209.85.64" nocase
        $port = "9090"
        $socket_connect = /socket\.connect\(\([\s\S]*?\)\)/
    condition:
        $ip and $port and $socket_connect
}