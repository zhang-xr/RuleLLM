rule Malicious_Exfiltration_Base64_EnvVars {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects environment variables, encodes them in Base64, and exfiltrates via HTTP POST"
        confidence = 90
        severity = 80

    strings:
        $os_environ = "os.environ" ascii
        $base64_encode = "base64.b64encode" ascii
        $http_post = "requests.post" ascii
        $data_dict = /data\s*=\s*{.*}/ ascii

    condition:
        all of them and
        $os_environ in (0..100) and
        $base64_encode in (0..100) and
        $http_post in (0..100)
}