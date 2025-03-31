rule Python_EnvironmentExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code exfiltrating environment variables"
        confidence = 85
        severity = 80

    strings:
        $requests_import = "import requests"
        $env_data = /env_data\s*=\s*\{key:\s*value\s*for\s*key,\s*value\s*in\s*os\.environ\.items\(\)\}/
        $http_post = /requests\.post\(\"http:\/\/[^\"]+\",\s*json\s*=\s*env_data/

    condition:
        $requests_import and $env_data and $http_post
}