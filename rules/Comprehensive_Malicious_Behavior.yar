rule Comprehensive_Malicious_Behavior {
    meta:
        author = "RuleLLM"
        description = "Comprehensive detection of base64-decoded URL, SSL context bypass, and outbound network communication"
        confidence = 95
        severity = 90
    strings:
        $base64_decode = "base64.b64decode"
        $ssl_context = "ssl._create_unverified_context"
        $urllib_request = "urllib.request.urlopen"
        $gethostname = "socket.gethostname"
        $url_construction = /url\s*=\s*base64\.b64decode\([^)]+\)\.decode\(['"]utf\-8['"]\)\s*\+\s*['"][^'"]+['"]/
    condition:
        3 of them
}