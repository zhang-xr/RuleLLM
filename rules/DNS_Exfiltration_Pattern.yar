rule DNS_Exfiltration_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects DNS-based data exfiltration patterns in Python code"
        confidence = 95
        severity = 90
    strings:
        $dns_lookup = "socket.getaddrinfo"
        $domain_pattern = /[a-z0-9]{20,}\.(oastify|burp|interactsh)\.(com|sh|io)/
        $hex_chunk = /[a-f0-9]{60}/
        $random_id = /random\.randint\(36\s*\*\*\s*12,\s*\(36\s*\*\*\s*13\)\s*-\s*1\)/
    condition:
        all of them and
        filesize < 10KB
}