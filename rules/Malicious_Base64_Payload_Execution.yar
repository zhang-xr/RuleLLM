rule Malicious_Base64_Payload_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects execution of base64-encoded malicious payloads"
        confidence = 90
        severity = 85

    strings:
        $base64_decode = "base64.b64decode" ascii
        $exec_keyword = "exec(" ascii
        $tempfile_import = "import tempfile" ascii
        $requests_import = "import requests" ascii

    condition:
        all of ($base64_decode, $exec_keyword) and 
        any of ($tempfile_import, $requests_import)
}