rule Base64_Exec_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded executable payloads in Python scripts"
        confidence = 95
        severity = 90
    strings:
        $base64_start = "code = b\"\"\""
        $base64_end = "\"\"\""
        $exec_call = "exec(base64.b64decode"
        $import_base64 = "import base64"
    condition:
        all of ($base64_start, $base64_end, $exec_call, $import_base64) and 
        (#base64_start < #base64_end)
}