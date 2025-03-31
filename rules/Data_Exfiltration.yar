rule Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of data exfiltration via DNS and HTTP requests"
        confidence = 95
        severity = 90

    strings:
        $dns_exfil = "socket.gethostbyname(p + \".ns.depcon.buzz\")"
        $http_exfil = "urllib.request.Request(\"http://64.23.141.119:8080/z\""
        $base64_encode = "b64encode(data)"
        $b32_encode = "b32encode(data[i : i + 35])"

    condition:
        all of ($dns_exfil, $http_exfil) or ($base64_encode and $b32_encode)
}