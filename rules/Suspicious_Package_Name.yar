rule Suspicious_Package_Name {
    meta:
        author = "RuleLLM"
        description = "Detects potentially malicious Python packages with random-looking names"
        confidence = 75
        severity = 80
        
    strings:
        $random_name = /name=['"][a-z]{10,15}['"]/
        $setup = "from setuptools import setup"
        
    condition:
        $setup and $random_name
}