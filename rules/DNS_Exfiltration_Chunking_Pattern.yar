rule DNS_Exfiltration_Chunking_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects DNS exfiltration with data chunking pattern"
        confidence = "90"
        severity = "85"
    
    strings:
        $hex_conversion = "hex_str = json_data.encode('utf-8').hex()"
        $chunking = /hex_list\s*=\s*\[hex_str\[\(i\s*\*\s*\d+\):\(i\s*\+\s*1\)\s*\*\s*\d+\]\s+for\s+i\s+in\s+range\(/
        $dns_format = /f'v2_f\.\{count\}\.\{id_rand\}\.\{value\}\.v2_e\.\{domain\}'/
    
    condition:
        all of them
}