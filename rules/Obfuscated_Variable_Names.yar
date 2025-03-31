rule Obfuscated_Variable_Names {
    meta:
        author = "RuleLLM"
        description = "Detects use of obfuscated variable names"
        confidence = 70
        severity = 75
    strings:
        $obfuscated_var1 = "wopvEaTEcopFEavc"
        $obfuscated_var2 = "iOpvEoeaaeavocp"
        $obfuscated_var3 = "uocpEAtacovpe"
    condition:
        any of them
}