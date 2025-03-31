rule Potential_Typosquatting_Package {
    meta:
        author = "RuleLLM"
        description = "Detects potential typosquatting attempts in Python package names"
        confidence = 90
        severity = 80
    strings:
        $setup = "from setuptools import setup, find_packages"
        $suspicious_name = /name\s*=\s*["'][\w\s]*\.\s*[\w\s]*["']/
    condition:
        $setup and $suspicious_name and 
        filesize < 10KB
}