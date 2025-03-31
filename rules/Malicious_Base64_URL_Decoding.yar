rule Malicious_Base64_URL_Decoding {
    meta:
        author = "RuleLLM"
        description = "Detects malicious patterns involving base64-decoded URL construction"
        confidence = 85
        severity = 80
    strings:
        $base64_decode = "base64.b64decode"
        $url_construction = /url\s*=\s*base64\.b64decode\([^)]+\)\.decode\(['"]utf\-8['"]\)\s*\+\s*['"][^'"]+['"]/
    condition:
        all of them
}