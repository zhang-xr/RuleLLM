rule Malicious_EnvVar_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects environment variables and exfiltrates them via HTTP POST"
        confidence = 90
        severity = 85

    strings:
        $env_collect = "dict(os.environ)" ascii wide
        $urlencode = "urllib.parse.urlencode" ascii wide
        $post_request = "urllib.request.Request" ascii wide
        $urlopen = "urllib.request.urlopen" ascii wide
        $ngrok_url = /https?:\/\/[a-f0-9]{12}\.ngrok\.(io|app)/ ascii wide

    condition:
        all of them
}