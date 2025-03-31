rule Python_Multi_Layer_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects multiple layers of code obfuscation in Python"
        confidence = "90"
        severity = "85"
    
    strings:
        $lambda = /_=lambda\s+\w+:/
        $base64 = "base64.b64decode"
        $chr_chain = /\".join\(chr\(i\) for i in \[/
        $hex_str = /\\x[0-9a-f]{2}/
        $exec_family = /(eval|exec)\(/
    
    condition:
        3 of them
}