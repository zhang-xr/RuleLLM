rule Python_Obfuscation_Chr_Join {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using chr and join for potential obfuscation"
        confidence = 75
        severity = 55

    strings:
        $chr = "chr"
        $join = "join"
        $int = "int"

    condition:
        all of them
}