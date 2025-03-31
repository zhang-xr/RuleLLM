rule Malicious_Base64_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects base64 decoding and execution of malicious code"
        confidence = 90
        severity = 95
    strings:
        $base64_decode = "base64.b64decode"
        $exec_function = "exec("
    condition:
        all of them
}