rule Python_Base64_Marshal_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using base64 and marshal to execute obfuscated payloads"
        confidence = 90
        severity = 80

    strings:
        $base64 = "base64.b64decode"
        $marshal = "marshal.loads"
        $exec = "exec("
        $payload = /exec\(marshal\.loads\(base64\.b64decode\(.*?\)\)\)/

    condition:
        all of them and $payload
}