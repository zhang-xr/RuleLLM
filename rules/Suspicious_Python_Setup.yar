rule Suspicious_Python_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py patterns with potential malicious payload"
        confidence = "80"
        severity = "70"
    
    strings:
        $setup_call = /setup\(/
        $suspicious_requires = /install_requires\s*=\s*\[.*requests/
        $version_check = /python_requires\s*=\s*">=3\.[0-9]+"/
    
    condition:
        all of them and filesize < 10KB
}