rule Lambda_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects lambda functions used for obfuscation and dynamic code construction"
        confidence = 85
        severity = 75

    strings:
        $lambda_pattern = /lambda\s+\w+,\s*\w+:/ 
        $chr_int_pattern = /chr\(int\([^)]+\)\)/
        $join_pattern = /"".join\(/

    condition:
        $lambda_pattern and 
        $chr_int_pattern and 
        $join_pattern
}