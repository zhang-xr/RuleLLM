rule Suspicious_Fequests_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py configuration in fequests package"
        confidence = "85"
        severity = "80"
    
    strings:
        $package_name = "fequests"
        $requests_url = "https://requests.readthedocs.io"
        $requests_github = "https://github.com/psf/requests"
        $malicious_import = "from frequest import"
    
    condition:
        $package_name and 
        ($requests_url or $requests_github) and 
        $malicious_import
}