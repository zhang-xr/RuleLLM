rule Base64_Encoding_Sensitive_Data {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoding of sensitive data for exfiltration"
        confidence = 80
        severity = 75
    strings:
        $base64_encode = "base64.b64encode" ascii
        $sensitive_data = /(username|hostname|ip|flag)/ ascii
    condition:
        $base64_encode and $sensitive_data
}