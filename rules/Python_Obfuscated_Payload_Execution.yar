rule Python_Obfuscated_Payload_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts using base64 and marshal to execute obfuscated payloads"
        confidence = 90
        severity = 85

    strings:
        $base64_decode = "base64.b64decode"
        $marshal_loads = "marshal.loads"
        $exec_function = "exec("
        $payload_indicator = /base64\.b64decode\(["'].{20,}["']\)/

    condition:
        all of them and filesize < 10KB
}