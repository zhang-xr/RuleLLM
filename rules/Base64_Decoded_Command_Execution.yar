rule Base64_Decoded_Command_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 decoding followed by command execution in Python scripts"
        confidence = 90
        severity = 85

    strings:
        $b64decode = "base64.b64decode"
        $os_system = "os.system"
        $b64d_func = /def b64d\(.*base64_code.*\):/

    condition:
        $b64decode and $os_system and $b64d_func
}