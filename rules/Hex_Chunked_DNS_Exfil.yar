rule Hex_Chunked_DNS_Exfil {
    meta:
        author = "RuleLLM"
        description = "Detects hex-encoded data being chunked for DNS exfiltration"
        confidence = 92
        severity = 88
    strings:
        $hex_encode = ".encode('utf-8').hex()"
        $chunking = /\[hex_str\[(i \* \d+):(i \+ 1) \* \d+\] for i in range\(0, chunks \+ 1\)\]/
        $dns_template = /v2_f\.\d+\.\d+\.\w+\.v2_e\.\w+\.\w+/
    condition:
        all of them
}