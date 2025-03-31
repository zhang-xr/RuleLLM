rule Python_Marshal_Base64_Exec {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using marshal.loads with base64 decoding and exec"
        confidence = 90
        severity = 80
    strings:
        $marshal_base64 = /import\s+base64,\s*marshal;.*exec\(marshal\.loads\(base64\.b64decode\(/
    condition:
        $marshal_base64
}