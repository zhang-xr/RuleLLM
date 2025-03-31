rule Python_Setuptools_Backdoor_Install {
    meta:
        author = "RuleLLM"
        description = "Detects Python setuptools backdoor installation with network connection and shell spawning"
        confidence = 95
        severity = 90
    strings:
        $setuptools_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $socket_connect = /s\.connect\(\(["']\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}["'],\s*\d{1,5}\)\)/
        $pty_spawn = "pty.spawn(\"/bin/sh\")"
        $dup2_pattern = /os\.dup2\(s\.fileno\(\)\,\d\)/
    condition:
        3 of them and filesize < 10KB
}