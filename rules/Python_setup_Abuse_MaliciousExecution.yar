rule Python_setup_Abuse_MaliciousExecution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious code execution patterns in Python setup.py files"
        confidence = 85
        severity = 75

    strings:
        $setup_import = "from setuptools import setup"
        $tempfile_write = /_ttmp\.write\(b?\".*\"\)/
        $system_exec = /_ssystem\(f?\".*start.*pythonw\.exe.*\"\)/

    condition:
        all of them
}