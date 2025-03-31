rule Malicious_Python_Setup_Dependencies {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious dependencies in Python setup scripts"
        confidence = 85
        severity = 80
    strings:
        $suspicious_dependency = /pip\s+install\s+(pycryptodome|pyinstaller|py2exe)/ nocase
        $setup_script = "from setuptools import setup"
    condition:
        $setup_script and $suspicious_dependency
}