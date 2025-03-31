rule HTTP_POST_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that sends encoded data via HTTP POST request"
        confidence = 85
        severity = 75

    strings:
        $urlencode = "urllib.parse.urlencode(data)"
        $post_request = "urllib.request.Request(url, data=encoded_data)"
        $urlopen = "urllib.request.urlopen(req)"

    condition:
        all of them
}