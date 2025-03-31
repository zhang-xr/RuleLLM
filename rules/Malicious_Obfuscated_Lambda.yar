rule Malicious_Obfuscated_Lambda {
    meta:
        author = "RuleLLM"
        description = "Detects malicious lambda functions with string manipulation and eval patterns"
        confidence = 90
        severity = 85
        
    strings:
        $lambda_pattern = /_=lambda\s+\w+,\w+=/
        $eval_pattern = /eval\s*\(/
        $join_pattern = /\.join\s*\(chr\(int\(/
        $exec_pattern = /exec\s*\(/
        
    condition:
        all of them
}