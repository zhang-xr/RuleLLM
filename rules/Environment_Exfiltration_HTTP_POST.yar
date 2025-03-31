rule Environment_Exfiltration_HTTP_POST {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects environment variables and sends them via HTTP POST to a remote server"
        confidence = 90
        severity = 85

    strings:
        $env_collect = "dict(os.environ)" ascii wide
        $urlencode = "urllib.parse.urlencode" ascii wide
        $http_post = "urllib.request.Request" ascii wide
        $content_type = "Content-Type', 'application/x-www-form-urlencoded" ascii wide
        $urlopen = "urllib.request.urlopen" ascii wide
        $ngrok_url = /https:\/\/[a-f0-9]{12}\.ngrok\.app\// ascii wide

    condition:
        all of ($env_collect, $urlencode, $http_post, $content_type, $urlopen) and
        any of ($ngrok_url)
}