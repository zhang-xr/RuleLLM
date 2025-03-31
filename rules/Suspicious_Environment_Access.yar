rule Suspicious_Environment_Access {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious access to environment variables, often used in data exfiltration"
        confidence = 85
        severity = 80

    strings:
        $os_environ = "os.environ" ascii wide
        $dict_env = "dict(os.environ)" ascii wide
        $getenv = "os.getenv" ascii wide
        $urlencode = "urllib.parse.urlencode" ascii wide
        $http_post = "urllib.request.Request" ascii wide

    condition:
        (any of ($os_environ, $dict_env, $getenv)) and
        (any of ($urlencode, $http_post))
}