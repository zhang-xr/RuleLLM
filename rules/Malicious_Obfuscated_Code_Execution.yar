rule Malicious_Obfuscated_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated code execution patterns using eval or exec"
        confidence = 90
        severity = 85

    strings:
        $eval_pattern = /eval\s*\(.*\)/
        $exec_pattern = /exec\s*\(.*\)/
        $obfuscated_string = /".*[A-Za-z0-9]{20,}.*"/
        $chr_pattern = /chr\s*\(\s*\d+\s*\)/

    condition:
        any of ($eval_pattern, $exec_pattern) and 
        ($obfuscated_string or $chr_pattern)
}