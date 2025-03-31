rule Python_Setup_External_Communication {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that communicate with external domains during installation"
        confidence = 85
        severity = 75
    strings:
        $http_request = /requests\.get\s*\(\s*["'][^"']+["']/
        $external_domain = /https?:\/\/[a-zA-Z0-9.-]+\.(pipedream\.net|interactsh\.com|burpcollaborator\.net)/
    condition:
        $http_request and $external_domain
}