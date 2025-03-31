rule Suspicious_Lambda_Functions {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious lambda functions used for obfuscation"
        confidence = "85"
        severity = "80"
    
    strings:
        $lambda = "lambda" ascii wide
        $obfuscated_vars = /OO[0-9A-Za-z_]+/ ascii wide
        $chr_int = "chr(int(" ascii wide
    
    condition:
        all of ($lambda, $obfuscated_vars) and 
        any of ($chr_int)
}