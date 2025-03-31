rule Python_Suspicious_ImportChain {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious import chains used for code execution"
        confidence = 90
        severity = 85
    strings:
        $import1 = "__import__('builtins').exec"
        $import2 = "__import__('builtins').compile"
        $import3 = "__import__('base64').b64decode"
    condition:
        all of them
}