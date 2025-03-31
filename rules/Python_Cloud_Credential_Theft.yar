rule Python_Cloud_Credential_Theft {
    meta:
        author = "RuleLLM"
        description = "Detects Python code attempting to steal cloud credentials"
        confidence = 92
        severity = 95
    strings:
        $metadata_service = "http://metadata.google.internal"
        $token_pattern = /instance\/service-accounts\/[^\/]+\/token/
        $curl_post = "curl -X POST"
    condition:
        all of them
}