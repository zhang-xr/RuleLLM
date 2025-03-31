rule Python_Base64Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded data exfiltration in Python scripts"
        confidence = 95
        severity = 85
    strings:
        $base64_encode = "base64.b64encode"
        $base64_decode = "base64.b64decode"
        $remote_request = /requests\.get\s*\(.+base64_message/
        $data_construction = /\"ip\"\s*:.+\"host\"\s*:.+\"path\"\s*:/
    condition:
        ($base64_encode or $base64_decode) and ($remote_request or $data_construction)
}