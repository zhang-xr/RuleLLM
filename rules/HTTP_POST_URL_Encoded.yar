rule HTTP_POST_URL_Encoded {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP POST requests with URL-encoded data, often used in exfiltration"
        confidence = 85
        severity = 80

    strings:
        $urlencode = "urllib.parse.urlencode" ascii wide
        $http_post = "urllib.request.Request" ascii wide
        $content_type = "Content-Type', 'application/x-www-form-urlencoded" ascii wide

    condition:
        all of ($urlencode, $http_post, $content_type)
}