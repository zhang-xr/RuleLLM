rule Malicious_Python_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using eval() and compile() for dynamic execution, often seen in malware."
        confidence = 90
        severity = 80

    strings:
        $eval = "eval("
        $compile = "compile("
        $exec = "exec("
        $b64decode = "b64decode("
        $decode = ".decode("
        $obfuscated_string = /\\x[0-9a-f]{2}/

    condition:
        all of ($eval, $compile) or 
        (any of ($exec, $b64decode, $decode) and 
        $obfuscated_string)
}