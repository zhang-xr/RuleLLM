rule Base64_Obfuscation_Setup_Py {
    meta:
        author = "RuleLLM"
        description = "Detects Base64-encoded strings in Python setup.py scripts"
        confidence = 85
        severity = 80

    strings:
        $base64_decode = "base64.b64decode"
        $base64_string = /[A-Za-z0-9+\/]{20,}={0,2}/

    condition:
        $base64_decode and
        $base64_string
}