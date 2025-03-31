rule Lambda_With_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects lambda functions combined with obfuscation techniques"
        confidence = 90
        severity = 85

    strings:
        $lambda_pattern = /lambda\s+\w+.*:/
        $obfuscated_string = /".*[A-Za-z0-9]{20,}.*"/
        $chr_pattern = /chr\s*\(\s*\d+\s*\)/

    condition:
        $lambda_pattern and 
        ($obfuscated_string or $chr_pattern)
}