rule Python_ReverseShell_SetupTools {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup.py using setuptools to install reverse shell"
        confidence = 90
        severity = 95
        reference = "Analyzed code segment"
    
    strings:
        $setup_tools = "from setuptools import setup"
        $custom_install = "class CustomInstall(install)"
        $socket_import = "import socket"
        $pty_import = "import pty"
        $base64_encode = "base64.b64encode"
        $os_system = "os.system"
        $reverse_shell_pattern = /s\.connect\(\([\'\"].*[\'\"]\,\s*\d+\)\)/
    
    condition:
        all of ($setup_tools, $custom_install) and 
        3 of ($socket_import, $pty_import, $base64_encode, $os_system, $reverse_shell_pattern)
}