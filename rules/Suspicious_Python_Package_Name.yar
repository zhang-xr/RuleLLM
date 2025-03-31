rule Suspicious_Python_Package_Name {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package names that may indicate malicious intent"
        confidence = 80
        severity = 70
        
    strings:
        $package_name = /name\s*=\s*['"][a-z]{10,}['"]/
        
    condition:
        $package_name
}