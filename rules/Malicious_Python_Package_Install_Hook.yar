rule Malicious_Python_Package_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup using custom install hooks"
        confidence = 90
        severity = 80
    strings:
        $install_hook = "cmdclass={'develop': AfterDevelop, 'install': AfterInstall,}"
        $base64_decode = "base64.b64decode"
        $os_system = "os.system"
        $custom_hook = /(AfterDevelop|AfterInstall)/
    condition:
        all of them
}