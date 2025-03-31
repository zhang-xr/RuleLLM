rule Malicious_SystemInfo_Collection_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects collection and exfiltration of system information via base64 encoding and HTTP request"
        confidence = 90
        severity = 85
    strings:
        $os_login = "os.getlogin()" ascii
        $platform_node = "platform.node()" ascii
        $socket_ip = "socket.socket(socket.AF_INET, socket.SOCK_DGRAM)" ascii
        $base64_encode = "base64.b64encode" ascii
        $http_request = "http://" ascii
        $flag_read = "os.popen('cat /flag')" ascii
    condition:
        all of ($os_login, $platform_node, $socket_ip, $base64_encode) and
        any of ($http_request, $flag_read)
}