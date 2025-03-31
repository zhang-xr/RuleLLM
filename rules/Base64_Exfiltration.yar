rule Base64_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects base64-encoded data being used in URLs, often for exfiltration."
        confidence = 80
        severity = 70

    strings:
        $base64_encode = "base64.b64encode"
        $url_pattern = /https?:\/\/[^\s]+\?[a-zA-Z0-9+\/=]+/

    condition:
        $base64_encode and $url_pattern and
        filesize < 10KB
}