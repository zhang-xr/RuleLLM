rule Malicious_Python_Package_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with malicious install hooks that collect and exfiltrate system information"
        confidence = 90
        severity = 80
    strings:
        $class_def = "class CustomInstall(install):"
        $hostname = "socket.gethostname()"
        $cwd = "os.getcwd()"
        $username = "getpass.getuser()"
        $requests = "requests.get("
        $cmdclass = "cmdclass={'install': CustomInstall}"
    condition:
        all of them and filesize < 10KB
}