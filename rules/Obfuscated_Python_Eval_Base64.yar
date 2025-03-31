rule Obfuscated_Python_Eval_Base64 {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using eval and base64 decoding for obfuscation."
        confidence = 90
        severity = 80

    strings:
        $eval = "eval"
        $base64_decode = "b64decode"
        $obfuscated_string = /\\x[0-9a-f]{2}/
        $dynamic_import = "__import__"

    condition:
        any of them and
        filesize < 10KB and
        #eval > 1 and
        #base64_decode > 1
}