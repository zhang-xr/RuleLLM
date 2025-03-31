rule Python_SuspiciousSetup {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup with potential malicious intent"
        confidence = "80"
        severity = "75"
    
    strings:
        $setup = "from setuptools import setup, find_packages"
        $requests = "install_requires=['requests']"
        $version = /VERSION\s*=\s*[\'\"]\d+\.\d+\.\d+[\'\"]/
        $desc = "DESCRIPTION = 'Dependecy Confusion POC'"
    
    condition:
        $setup and $requests and 
        (1 of ($version, $desc))
}