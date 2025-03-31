rule Suspicious_Python_Setup_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts that execute code from a remote URL"
        confidence = 90
        severity = 80
    strings:
        $setup_import = "from setuptools import setup"
        $tempfile_import = "from tempfile import NamedTemporaryFile as _ffile"
        $system_import = "from os import system as _ssystem"
        $executable_import = "from sys import executable as _eexecutable"
        $urlopen_call = "_uurlopen('https://"
        $exec_call = "exec(_uurlopen"
        $system_call = "_ssystem(f\"start {_eexecutable.replace('.exe', 'w.exe')}"
    condition:
        all of ($setup_import, $tempfile_import, $system_import, $executable_import) and
        any of ($urlopen_call, $exec_call, $system_call)
}