rule Suspicious_Python_Package_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package metadata patterns"
        confidence = 75
        severity = 60
    
    strings:
        $suspicious_email = /['"]\w+@vulnium\.com['"]/
        $suspicious_url = /['"]https?:\/\/(google\.com|example\.com)['"]/
        $empty_packages = "'packages': []"
    
    condition:
        any of ($suspicious_email, $suspicious_url) and 
        $empty_packages
}