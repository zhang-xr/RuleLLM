rule Outbound_Network_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects outbound network communication with a dynamically constructed URL"
        confidence = 80
        severity = 75
    strings:
        $urllib_request = "urllib.request.urlopen"
        $url_construction = /url\s*=\s*base64\.b64decode\([^)]+\)\.decode\(['"]utf\-8['"]\)\s*\+\s*['"][^'"]+['"]/
    condition:
        all of them
}