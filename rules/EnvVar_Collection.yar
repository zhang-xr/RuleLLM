rule EnvVar_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects environment variables using os.environ"
        confidence = 80
        severity = 60

    strings:
        $env_collection = "data = dict(os.environ)"

    condition:
        $env_collection
}