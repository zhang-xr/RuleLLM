rule HTTP_Request_With_Dynamic_Hostname {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests that use dynamic hostnames"
        confidence = 80
        severity = 75

    strings:
        $requests_get = "requests.get("
        $socket_gethostname = "socket.gethostname()"

    condition:
        $requests_get and $socket_gethostname
}