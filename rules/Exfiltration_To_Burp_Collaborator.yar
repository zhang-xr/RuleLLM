rule Exfiltration_To_Burp_Collaborator {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP requests to Burp Collaborator domains for exfiltration"
        confidence = 95
        severity = 90

    strings:
        $burp_domain = /https?:\/\/[a-z0-9]{16,32}\.burpcollaborator\.net/
        $requests_get = "requests.get"

    condition:
        $requests_get and $burp_domain
}