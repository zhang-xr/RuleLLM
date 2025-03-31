rule Suspicious_HTTP_POST_DynamicDomain {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP POST requests to dynamically generated or suspicious domains"
        confidence = 85
        severity = 75

    strings:
        $http_post = "requests.post" ascii
        $dynamic_domain = /http:\/\/[a-z0-9]{16,}\.oast\.fun/ ascii

    condition:
        all of them
}