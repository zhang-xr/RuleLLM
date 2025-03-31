rule Env_Collection_And_Encoding {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects environment variables and encodes them."
        confidence = 80
        severity = 70

    strings:
        $env_collect = "os.environ" ascii
        $base64_encode = "base64.b64encode" ascii

    condition:
        all of them
}