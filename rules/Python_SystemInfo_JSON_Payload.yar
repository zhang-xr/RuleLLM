rule Python_SystemInfo_JSON_Payload {
    meta:
        author = "RuleLLM"
        description = "Detects JSON payloads containing system information in Python scripts"
        confidence = 85
        severity = 75
    strings:
        $json_payload = /\{.*?"package_name":.*?"version":.*?"user":.*?"cwd":.*?"hostname":.*?\}/
        $post_request = /requests\.post\(.*?\{.*?\}.*?\)/
    condition:
        $json_payload and $post_request
}