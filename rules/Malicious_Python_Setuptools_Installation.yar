rule Malicious_Python_Setuptools_Installation {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setuptools installation script with Base64-encoded payload execution"
        confidence = "90"
        severity = "80"
    
    strings:
        $b64d_func = "def b64d(base64_code):"
        $os_system = "os.system"
        $base64_decode = "base64.b64decode"
        $setuptools_cmdclass = "cmdclass={'develop': AfterDevelop, 'install': AfterInstall}"
        $github_url = "https://github.com/Exet75/neofetch/blob/main/ip_checker.exe?raw=true"
        $stealer_exe = "STEALER.exe"
    
    condition:
        all of them
}