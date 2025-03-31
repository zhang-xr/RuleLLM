rule Suspicious_Domain_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP POST requests to suspicious, randomly generated domains."
        confidence = 95
        severity = 90

    strings:
        $suspicious_domain = /http:\/\/[a-z0-9]{32,}\.oast\.fun/ ascii
        $http_post = "requests.post" ascii

    condition:
        all of them
}