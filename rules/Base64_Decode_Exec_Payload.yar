rule Base64_Decode_Exec_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded payloads that are decoded and executed."
        confidence = 90
        severity = 90

    strings:
        $base64_import = "import base64"
        $base64_decode = "base64.b64decode("
        $exec = "exec("
        $code_var = "code = b\"\"\""

    condition:
        all of them
}