rule Data_Exfiltration_DNS_HTTP {
    meta:
        author = "RuleLLM"
        description = "Detects data exfiltration using DNS queries and HTTP POST requests"
        confidence = 90
        severity = 85

    strings:
        $dns_query = /[a-zA-Z0-9]{2}[0-9a-f]{1,2}-[A-Z2-7]+\.ns\.depcon\.buzz/
        $http_post = "http://64.23.141.119:8080/z"
        $b64encode = "b64encode"
        $b32encode = "b32encode"
        $urllib_request = "urllib.request.Request"
        $socket_gethostbyname = "socket.gethostbyname"

    condition:
        all of ($dns_query, $http_post, $b64encode, $b32encode) and 
        any of ($urllib_request, $socket_gethostbyname)
}