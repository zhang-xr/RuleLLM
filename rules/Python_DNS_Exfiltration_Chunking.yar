rule Python_DNS_Exfiltration_Chunking {
    meta:
        author = "RuleLLM"
        description = "Detects DNS exfiltration with chunking pattern"
        confidence = 95
        severity = 90
    strings:
        $dns_query = /socket\.getaddrinfo\([^,]+,\s*80\)/
        $hex_chunking = /\[\w\[\(i\s*\*\s*\d+\):\(i\s*\+\s*1\)\s*\*\s*\d+\]\s*for\s*i\s*in\s*range\(/
        $data_dict = /\{\s*['"]\w['"]\s*:/
    condition:
        all of them
}