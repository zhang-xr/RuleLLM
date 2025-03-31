rule Suspicious_EnvVar_HTTP_Activity {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious use of environment variables combined with HTTP communication"
        confidence = 85
        severity = 80

    strings:
        $env_collect = "os.environ" ascii wide
        $http_request = "urllib.request" ascii wide
        $urlencode = "urllib.parse.urlencode" ascii wide

    condition:
        $env_collect and ($http_request or $urlencode)
}