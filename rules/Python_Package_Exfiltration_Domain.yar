rule Python_Package_Exfiltration_Domain {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with suspicious domain patterns in exfiltration URLs"
        confidence = 95
        severity = 90
    strings:
        $domain = /[a-z0-9]{32}\.(oastify|burpcollaborator|interactsh|pipedream)\.(com|net)/
    condition:
        $domain
}