rule Suspicious_Python_Package_Name {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package names often used in malicious packages"
        confidence = "85"
        severity = "80"
    
    strings:
        $suspicious_name = /[a-z]{10,}[0-9]{4,}/
        $setup_import = "from setuptools import setup"
        $cmd_override = /cmdclass\s*=\s*\{/
    
    condition:
        filesize < 20KB and
        $setup_import and
        $cmd_override and
        $suspicious_name
}