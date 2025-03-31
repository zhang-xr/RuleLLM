rule Complex_Obfuscation_Dynamic_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with complex obfuscation and dynamic execution patterns."
        confidence = 95
        severity = 90

    strings:
        $eval = "eval"
        $compile = "compile"
        $exec = "exec"
        $base64 = "base64"
        $hex_string = /\\x[0-9a-f]{2}/

    condition:
        all of them and
        filesize < 15KB
}