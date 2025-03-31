rule Malicious_Python_BlankOBF_Eval_Base64 {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using BlankOBF obfuscation, dynamic evaluation, and base64 decoding."
        confidence = 90
        severity = 80

    strings:
        $blankobf_comment = "Obfuscated with BlankOBF"
        $eval_pattern = /eval\s*\(.*\)/
        $b64decode = /b64decode\s*\(.*\)/
        $hex_string = /\\x[0-9a-f]{2}/
        $dynamic_import = "__import__"

    condition:
        $blankobf_comment and ($eval_pattern or $b64decode) and ($hex_string or $dynamic_import)
}