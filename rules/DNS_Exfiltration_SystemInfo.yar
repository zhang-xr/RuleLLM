rule DNS_Exfiltration_SystemInfo {
    meta:
        author = "RuleLLM"
        description = "Detects DNS-based exfiltration of system information in Python scripts"
        confidence = "85"
        severity = "80"
    
    strings:
        $dns_subdomain = "doit(\"socket\", \"getho\", \"stbyname\")(subdomain)"
        $content_format = "f\"{username}|{host}|{pwd}\""
        $subdomain_format = "f\"{b64}.{l}\""
    
    condition:
        all of them
}