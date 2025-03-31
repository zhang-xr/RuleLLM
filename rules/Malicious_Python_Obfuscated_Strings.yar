rule Malicious_Python_Obfuscated_Strings {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using chr and join to construct obfuscated strings."
        confidence = "80"
        severity = "85"

    strings:
        $chr = "chr"
        $join = "join"
        $eval = "eval"
        $exec = "exec"

    condition:
        all of ($chr, $join) and 
        any of ($eval, $exec)
}