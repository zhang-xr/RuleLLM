rule Malicious_HTTP_Request {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests to dynamically constructed URLs in Python scripts"
        confidence = 85
        severity = 75
    strings:
        $urllib_import = "import urllib.request"
        $urlopen_call = "urllib.request.urlopen"
        $base64_decode = "base64.b64decode"
    condition:
        $urllib_import and $urlopen_call and $base64_decode
}