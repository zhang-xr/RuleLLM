rule DNS_Chunk_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects DNS chunking patterns for data exfiltration"
        confidence = 90
        severity = 85
    strings:
        $hex_chunk = /hex_str\[\d+ \* 60\):\(\d+ \+ 1\) \* 60\]/
        $dns_format = /v2_f\.\d+\.\d+\.\w+\.v2_e\.\w+/
    condition:
        filesize < 10KB and 
        all of them
}