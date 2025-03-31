rule Malicious_EnvVar_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects environment variables and exfiltrates them via HTTP POST"
        confidence = 90
        severity = 80

    strings:
        $env_collection = "data = dict(os.environ)"
        $urlencode = "urllib.parse.urlencode(data)"
        $post_request = "urllib.request.Request(url, data=encoded_data)"
        $urlopen = "urllib.request.urlopen(req)"
        $ngrok_url = /https:\/\/[a-zA-Z0-9]+\.ngrok\.app\/[a-zA-Z0-9_\/]+/

    condition:
        all of them
}