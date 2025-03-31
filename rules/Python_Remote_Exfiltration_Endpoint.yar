rule Python_Remote_Exfiltration_Endpoint {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts sending data to suspicious remote endpoints."
        confidence = 90
        severity = 85

    strings:
        $remote_endpoint = /https?:\/\/[a-zA-Z0-9.-]+\.(pipedream\.net|interactsh\.com|burpcollaborator\.net)/

    condition:
        $remote_endpoint
}