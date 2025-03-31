rule Base64_Encode_EnvVars {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoding of environment variables, often used for exfiltration"
        confidence = 80
        severity = 70

    strings:
        $os_environ = "os.environ" ascii
        $base64_encode = "base64.b64encode" ascii

    condition:
        all of them and
        $os_environ in (0..100) and
        $base64_encode in (0..100)
}