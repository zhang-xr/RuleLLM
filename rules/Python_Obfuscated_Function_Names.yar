rule Python_Obfuscated_Function_Names {
    meta:
        author = "RuleLLM"
        description = "Detects Python malware with obfuscated function names"
        confidence = 80
        severity = 70

    strings:
        $obf_func = /_____\(/
        $obf_func2 = /_______\(/

    condition:
        (1 of ($obf_func, $obf_func2))
}