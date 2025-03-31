rule Python_MaliciousSetup_Base64Payload {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup.py with base64 encoded payload in install command"
        confidence = 95
        severity = 90
    strings:
        $install_class = "class InstallCommand(install):"
        $base64_exec = /exec\(__import__\('base64'\)\.b64decode\([\"'][A-Za-z0-9+\/]+={0,2}[\"']\)\)/
        $setup_cmdclass = "cmdclass={'install': InstallCommand}"
    condition:
        all of them and filesize < 10KB
}