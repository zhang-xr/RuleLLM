rule Python_Exfiltration_To_Specific_Server {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts sending data to a specific remote server (https://0v0.in/pypi/)"
        confidence = 90
        severity = 80
    strings:
        $server_url = "https://0v0.in/pypi/"
        $post_request = /requests\.post\(.*?\{.*?\}.*?\)/
    condition:
        $server_url and $post_request
}