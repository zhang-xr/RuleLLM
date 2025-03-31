rule Suspicious_PackageSetup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious package setup with potential malicious dependencies"
        confidence = "85"
        severity = "70"
    strings:
        $setup_call = "setup("
        $malicious_dependency = /"requests>=2\.\d+\.\d+"/
    condition:
        $setup_call and $malicious_dependency
}