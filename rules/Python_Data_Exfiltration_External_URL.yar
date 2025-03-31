rule Python_Data_Exfiltration_External_URL {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that send data to external URLs using HTTP POST requests."
        confidence = 90
        severity = 80
    strings:
        $requests_post = "requests.post"
        $http_url = /https?:\/\/[^\s"]+/
        $json_payload = /"json":\s*{/
    condition:
        all of ($requests_post, $http_url, $json_payload)
}