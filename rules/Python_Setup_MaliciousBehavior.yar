rule Python_Setup_MaliciousBehavior {
    meta:
        author = "RuleLLM"
        description = "Detects malicious patterns in Python setup.py files"
        confidence = "90"
        severity = "85"
    
    strings:
        $setup_import = "from setuptools import setup"
        $custom_install = "class CustomInstallCommand"
        $malicious_install = /def run\(self\):[\s\S]{1,500}eval\(compile\(/
        $long_encoded = /[\x00-\x1F\x7F-\xFF]{100,}/
    
    condition:
        $setup_import and 
        ($custom_install and $malicious_install) or 
        $long_encoded
}