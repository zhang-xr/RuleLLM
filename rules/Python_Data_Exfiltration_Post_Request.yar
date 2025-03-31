rule Python_Data_Exfiltration_Post_Request {
    meta:
        author = "RuleLLM"
        description = "Detects a POST request in Python that sends user data to a remote server"
        confidence = 85
        severity = 75

    strings:
        $post_request = /requests\.post\(.*\,.*data\s*\=\s*\{.*\"username\"\s*\:\s*\w+.*\}/

    condition:
        $post_request
}