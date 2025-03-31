rule DNS_Tunneling_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects DNS tunneling patterns for data exfiltration"
        confidence = 85
        severity = 85
    strings:
        $dns_prefix = "prefix + hex(j)[2:] + \"-\" + segment"
        $dns_resolve = "socket.gethostbyname("
        $dns_domain = ".ns.depcon.buzz"
    condition:
        all of them
}