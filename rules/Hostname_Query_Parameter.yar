rule Hostname_Query_Parameter {
    meta:
        author = "RuleLLM"
        description = "Detects the fetching of hostname and its use as a query parameter in a URL"
        confidence = 75
        severity = 65
    strings:
        $gethostname = "socket.gethostname"
        $query_param = /url\s*=\s*[^+]+\+\s*['"]\?h=['"]\s*\+\s*hostname/
    condition:
        all of them
}