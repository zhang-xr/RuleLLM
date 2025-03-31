rule Obfuscated_String_Patterns {
    meta:
        author = "RuleLLM"
        description = "Detects obfuscated string patterns commonly used in malicious Python scripts."
        confidence = 80
        severity = 75

    strings:
        $obfuscated_string = /\\x[0-9a-f]{2}/
        $join_chr = /\.join\s*\(chr\s*\(/

    condition:
        $obfuscated_string and $join_chr
}