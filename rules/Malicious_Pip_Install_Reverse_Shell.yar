rule Malicious_Pip_Install_Reverse_Shell {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python pip install scripts that execute reverse shells"
        confidence = 90
        severity = 95
    strings:
        $setup = "setup("
        $cmdclass = "cmdclass={'install':"
        $base64_decode = "base64 -d|bash"
        $reverse_shell = "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)"
    condition:
        all of ($setup, $cmdclass) and any of ($base64_decode, $reverse_shell)
}