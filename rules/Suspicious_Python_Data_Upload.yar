rule Suspicious_Python_Data_Upload {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that uploads data to potentially suspicious domains"
        confidence = 80
        severity = 70
    strings:
        $requests_post = "requests.post("
        $json_payload = /"package_name":\s*".+",\s*"version":\s*".+",\s*"user"/
        $https_url = /https:\/\/[^\/]+\//
    condition:
        all of them
}