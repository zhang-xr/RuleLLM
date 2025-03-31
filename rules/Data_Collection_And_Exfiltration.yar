rule Data_Collection_And_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of data collection and exfiltration via DNS tunneling"
        confidence = 95
        severity = 90
    strings:
        $hostname = "socket.gethostname()"
        $external_ip = "external_ip()"
        $walk_cwd = "walk_cwd()"
        $compress = "compress("
        $b32encode = "b32encode("
        $dns_query = ".ns.depcon.buzz"
    condition:
        4 of them
}