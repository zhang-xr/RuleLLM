rule Python_EnvVar_Exfiltration_HTTP {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects environment variables and sends them via HTTP POST request."
        confidence = 90
        severity = 80

    strings:
        $env_collect = "dict(os.environ)" nocase
        $urlencode = "urllib.parse.urlencode" nocase
        $http_post = "urllib.request.Request" nocase
        $urlopen = "urllib.request.urlopen" nocase

    condition:
        all of them and
        filesize < 10KB
}