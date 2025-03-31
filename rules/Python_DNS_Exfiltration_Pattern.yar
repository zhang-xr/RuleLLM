rule Python_DNS_Exfiltration_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects DNS-based data exfiltration patterns in Python code"
        confidence = "95"
        severity = "85"
    
    strings:
        $dns_header = /\x00\x01\x00\x00\x00\x00\x00\x00/
        $hex_chunk = /[\da-f]{60}/
        $domain_pattern = /[\w-]{12,}\.[a-z]{2,}/
        $dns_socket = /socket\.socket\(socket\.AF_INET,\s*socket\.SOCK_DGRAM\)/
        $random_id = /random\.randint\(\d{12,},\s*\d{13,}\)/
    
    condition:
        filesize < 100KB and
        all of ($dns_socket, $domain_pattern) and
        2 of ($dns_header, $hex_chunk, $random_id)
}