rule python_dependency_confusion_system_info_collection {
    meta:
        author = "RuleLLM"
        description = "Detects collection of system information in Python setup.py files"
        confidence = 85
        severity = 75

    strings:
        $hostname = "socket.gethostname()"
        $cwd = "os.getcwd()"
        $username = "getpass.getuser()"
        $dict_assignment = /\{\s*['"]hostname['"]\s*:\s*hostname\s*,\s*['"]cwd['"]\s*:\s*cwd\s*,\s*['"]username['"]\s*:\s*username\s*\}/

    condition:
        all of ($hostname, $cwd, $username) and
        $dict_assignment
}