rule Suspicious_Python_Setuptools_With_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setuptools setup combined with suspicious subprocess execution"
        confidence = 85
        severity = 80
    strings:
        $setup = "from setuptools import setup"
        $subprocess = "subprocess.run"
        $powershell = "powershell"
        $curl = "curl.exe"
    condition:
        all of them and filesize < 10KB
}