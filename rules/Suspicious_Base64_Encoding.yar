rule Suspicious_Base64_Encoding {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoding of collected system information with suspicious prefix"
        confidence = 85
        severity = 75
    strings:
        $base64_encode = "base64.b64encode" ascii
        $suspicious_prefix = /encode\s*=\s*['"]Zx[23]/ ascii
    condition:
        all of them
}