rule Suspicious_Python_Package_Domain {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious domains used in Python package code for data exfiltration"
        confidence = 95
        severity = 85
    strings:
        $suspicious_domain = "o2zel35m.requestrepo.com" nocase
        $http_request = "requests.get("
    condition:
        $suspicious_domain and
        $http_request in (@http_request..@http_request + 100)
}