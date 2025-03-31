rule Python_Base64_Obfuscation {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 obfuscation in Python scripts"
        confidence = 85
        severity = 80

    strings:
        $base64_decode = "base64.b64decode"
        $encoded_host = /base64\.b64decode\("[A-Za-z0-9+\/=]+"\)/
        $encoded_port = /base64\.b64decode\("[A-Za-z0-9+\/=]+"\)/

    condition:
        all of them
}