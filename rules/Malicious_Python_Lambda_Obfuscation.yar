rule Malicious_Python_Lambda_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious lambda functions with obfuscation"
        confidence = 80
        severity = 75

    strings:
        $lambda_pattern = /lambda\s+\w+:\s*'.*'/
        $chr_pattern = /chr\s*\(\s*\d+\s*\)/
        $eval_pattern = /eval\s*\(.*\)/

    condition:
        $lambda_pattern and 
        any of ($chr_pattern, $eval_pattern)
}