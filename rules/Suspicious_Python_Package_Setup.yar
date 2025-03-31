rule Suspicious_Python_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup with potential malicious code"
        confidence = "90"
        severity = "85"
    strings:
        $package_name = "tdwTauthAuthentication"
        $version = "1.0.9"
        $requests_dep = "\"requests>=2.27.1\""
        $setup_call = "setup(" nocase
    condition:
        $setup_call and $package_name and $version and $requests_dep
}