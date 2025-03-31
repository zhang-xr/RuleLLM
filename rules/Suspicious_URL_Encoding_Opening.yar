rule Suspicious_URL_Encoding_Opening {
    meta:
        author = "RuleLLM"
        description = "Detects URL encoding and opening in a suspicious context"
        confidence = 80
        severity = 70
    strings:
        $urlencode = "urllib.parse.urlencode"
        $urlopen = "urllib.request.urlopen"
        $webhook_url = /https?:\/\/[^\s"]+/ 
    condition:
        $urlencode and $urlopen and $webhook_url
}