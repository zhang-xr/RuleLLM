rule Python_ReverseShell_Setuptools_Install {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python reverse shell embedded in setuptools install command"
        confidence = 90
        severity = 95

    strings:
        $install_class = "class CustomInstall(install)"
        $reverse_shell = "python3 -c \"import os; import pty; import socket; s = socket.socket(socket.AF_INET, socket.SOCK_STREAM); s.connect(("
        $base64_exec = "os.system('echo %s|base64 -d|bash'"
        $cmdclass = "cmdclass={'install': CustomInstall}"

    condition:
        all of them
}