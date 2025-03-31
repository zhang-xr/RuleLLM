rule Suspicious_DNS_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects DNS-based data exfiltration patterns using encoded subdomains"
        confidence = "95"
        severity = "90"
    strings:
        $dns_lookup = "socket.gethostbyname" ascii
        $b32_encode = "b32encode(data[i : i + 35])" ascii
        $domain_pattern = /\.ns\.depcon\.buzz/ ascii
    condition:
        all of them
}