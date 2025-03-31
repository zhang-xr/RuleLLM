rule Malicious_Env_Exfiltration_Base64 {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects environment variables, encodes them in Base64, and sends them to a remote server."
        confidence = 90
        severity = 80

    strings:
        $env_collect = "os.environ" ascii
        $base64_encode = "base64.b64encode" ascii
        $http_post = "requests.post" ascii
        $data_dict = /data\s*=\s*\{.*\}/ ascii

    condition:
        all of them and
        filesize < 10KB
}