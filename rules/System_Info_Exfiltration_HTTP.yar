rule System_Info_Exfiltration_HTTP {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information and exfiltrates it via HTTP"
        confidence = 90
        severity = 80

    strings:
        $os_uname = "os.uname()"
        $os_getcwd = "os.getcwd()"
        $socket_gethostname = "socket.gethostname()"
        $requests_get = "requests.get("
        $http_url = /http:\/\/[a-zA-Z0-9.-]+\.22\.ax\//

    condition:
        all of ($os_uname, $os_getcwd, $socket_gethostname, $requests_get) and
        $http_url
}