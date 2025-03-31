rule Python_Base64_Decode_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects base64 decoding followed by execution in Python scripts"
        confidence = 85
        severity = 75
    strings:
        $base64_decode = "base64.b64decode"
        $os_system = "os.system"
        $base64_string = /[A-Za-z0-9+\/]{20,}={0,2}/
    condition:
        $base64_decode and $os_system and $base64_string
}