rule Dependency_Confusion_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python package setup with DNS-based data exfiltration pattern"
        confidence = 90
        severity = 80
    strings:
        $setup_import = "from setuptools import setup"
        $custom_install = "class CustomInstall(install)"
        $dns_exfil = /socket\.getaddrinfo\([^,]+,\s*80\)/
        $data_collection = /'[phdc]':\s*\[[^\]]+\]/
        $hex_encode = /\.encode\('utf-8'\)\.hex\(\)/
    condition:
        all of them and
        filesize < 10KB
}