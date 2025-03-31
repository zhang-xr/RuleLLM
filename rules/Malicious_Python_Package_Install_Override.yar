rule Malicious_Python_Package_Install_Override {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that override setuptools install command to execute malicious code"
        confidence = 95
        severity = 90

    strings:
        $install_class = "class AfterInstall(install):"
        $develop_class = "class AfterDevelop(develop):"
        $cmdclass_dict = "cmdclass={"
        $os_system = "os.system"
        $b64decode = "base64.b64decode"

    condition:
        all of them and
        $install_class and
        $os_system and
        $b64decode
}