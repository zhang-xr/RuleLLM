rule Python_Malicious_Setup_RemoteExecution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts that download and execute remote code"
        confidence = 95
        severity = 90
        reference = "Analyzed code segment"
    
    strings:
        $setup_import = "from setuptools import setup"
        $tempfile_import = "from tempfile import NamedTemporaryFile"
        $system_import = "from os import system"
        $exec_import = "from sys import executable"
        $urlopen_pattern = /from urllib\.request import urlopen as _?u?urlopen/
        $exec_pattern = /exec\(_?u?urlopen\(['"].+['"]\)\.read\(\)\)/
        $system_call = /_?ssystem\(f?["']start ["']?{_?eexecutable\.replace\(['"]\.exe['"], ['"]w\.exe['"]\)}/
    
    condition:
        all of ($setup_import, $tempfile_import, $system_import, $exec_import) and
        2 of ($urlopen_pattern, $exec_pattern, $system_call)
}