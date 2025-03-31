rule python_dependency_confusion_custom_install {
    meta:
        author = "RuleLLM"
        description = "Detects custom install class with exfiltration behavior in Python setup.py files"
        confidence = 90
        severity = 80

    strings:
        $install_class = "class CustomInstall(install):"
        $run_method = "def run(self):"
        $hostname = "socket.gethostname()"
        $cwd = "os.getcwd()"
        $username = "getpass.getuser()"
        $requests_get = "requests.get("
        $params = "params ="

    condition:
        all of ($install_class, $run_method) and
        2 of ($hostname, $cwd, $username) and
        all of ($requests_get, $params)
}