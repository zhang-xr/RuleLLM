rule EnvVar_Post_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that exfiltrates environment variables via HTTP POST"
        confidence = 90
        severity = 85

    strings:
        $env_collect = "os.environ" ascii wide
        $post_request = "urllib.request.Request" ascii wide
        $urlopen = "urllib.request.urlopen" ascii wide

    condition:
        $env_collect and $post_request and $urlopen
}