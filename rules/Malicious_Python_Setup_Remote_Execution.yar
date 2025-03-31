rule Malicious_Python_Setup_Remote_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that attempt to download and execute remote code"
        confidence = 90
        severity = 95

    strings:
        $setup = "from setuptools import setup"
        $urlopen = "from urllib.request import Request, urlopen"
        $exec = "exec(urlopen(Request(url="
        $tempfile = "from tempfile import NamedTemporaryFile"
        $system = "from os import system"
        $python_exec = "start {_eexecutable.replace('.exe', 'w.exe')} {_ttmp.name}"

    condition:
        all of them and
        filesize < 10KB
}