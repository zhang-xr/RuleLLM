rule System_Info_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects and exfiltrates system information to a remote server."
        confidence = "95"
        severity = "90"

    strings:
        $os_login = "os.getlogin()"
        $platform_node = "platform.node()"
        $platform_platform = "platform.platform()"
        $socket_connect = "s.connect(("
        $base64_encode = "base64.b64encode("
        $http_request = "request(url='http://"

    condition:
        all of them
}