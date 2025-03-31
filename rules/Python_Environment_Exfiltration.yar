rule Python_Environment_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects environment variables and encodes them in Base64 for potential exfiltration."
        confidence = "90"
        severity = "80"

    strings:
        $env_collect = "os.environ"
        $base64_encode = "base64.b64encode"
        $http_post = "requests.post"

    condition:
        all of them
}