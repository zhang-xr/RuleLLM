rule Malicious_SystemInfo_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information including username, hostname, and IP address"
        confidence = 90
        severity = 80
    strings:
        $os_login = "os.getlogin()" ascii
        $platform_node = "platform.node()" ascii
        $socket_ip = /s\.getsockname\(\)\[0\]/ ascii
        $system_info = /System Info:.*Login Name:.*Host Name:.*IP:/ ascii
    condition:
        all of them
}