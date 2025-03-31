rule Python_Package_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup.py files that download and execute remote code"
        confidence = "95"
        severity = "90"
    
    strings:
        $setup = "from setuptools import setup"
        $tempfile = "from tempfile import NamedTemporaryFile"
        $urlopen = "from urllib.request import urlopen"
        $exec_pattern = /exec\([^\)]+\.read\(\)\)/
        $system_call = /_ssystem\(f"start {_eexecutable/
        
    condition:
        all of ($setup, $tempfile) and 
        any of ($urlopen, $exec_pattern) and
        $system_call
}