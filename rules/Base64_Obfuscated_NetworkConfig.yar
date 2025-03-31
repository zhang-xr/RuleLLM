rule Base64_Obfuscated_NetworkConfig {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded network configuration strings in Python code"
        confidence = 80
        severity = 85

    strings:
        $base64_import = "import base64"
        $base64_decode = "base64.b64decode"
        $encoded_ip = /base64\.b64decode\(\s*"[^"]*"\s*\)/
        $encoded_port = /base64\.b64decode\(\s*"[^"]*"\s*\)/

    condition:
        all of ($base64_import, $base64_decode) and
        any of ($encoded_ip, $encoded_port)
}