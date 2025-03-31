rule Suspicious_HTTP_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests with encoded system information in parameters"
        confidence = 95
        severity = 90
        
    strings:
        $urllib_parse_urlencode = "urllib.parse.urlencode"
        $urllib_request_urlopen = "urllib.request.urlopen"
        $base64_b64encode = "base64.b64encode"
        $suspicious_urls = /http:\/\/[a-z0-9\-\.]+\.(oast|byted-dast)\.(com|fun)/
        
    condition:
        all of ($urllib_parse_urlencode, $urllib_request_urlopen, $base64_b64encode) and 1 of ($suspicious_urls)
}