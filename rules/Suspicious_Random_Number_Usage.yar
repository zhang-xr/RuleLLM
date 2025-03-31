rule Suspicious_Random_Number_Usage {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious usage of random numbers in obfuscated code"
        confidence = "80"
        severity = "75"
    
    strings:
        $random = "random.randint" ascii wide
        $lambda = "lambda" ascii wide
        $chr_int = "chr(int(" ascii wide
    
    condition:
        all of ($random, $lambda) and 
        any of ($chr_int)
}