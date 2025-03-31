rule Malicious_Python_Package_Heroku_Domain {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages connecting to suspicious Heroku domains"
        confidence = 80
        severity = 70
    strings:
        $heroku_domain = /https:\/\/[a-zA-Z0-9-]+\.herokuapp\.com/
    condition:
        $heroku_domain
}