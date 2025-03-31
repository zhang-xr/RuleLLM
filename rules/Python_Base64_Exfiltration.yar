rule Python_Base64_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Base64-encoded strings and functions used to encode system information for potential exfiltration."
        confidence = 85
        severity = 75

    strings:
        $base64_func = "def to_base64_subdomain(input_string):"
        $base64_encode = "base64.urlsafe_b64encode"
        $base64_decode = "base64.b64decode"
        $encoded_string = /[A-Za-z0-9+\/]{20,}={0,2}/

    condition:
        ($base64_func or $base64_encode or $base64_decode) and 
        any of ($encoded_string)
}