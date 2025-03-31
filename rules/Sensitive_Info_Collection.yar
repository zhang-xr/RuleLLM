rule Sensitive_Info_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects collection of hostname, username, and current working directory"
        confidence = 85
        severity = 75

    strings:
        $hostname = "socket.gethostname()"
        $username = "getpass.getuser()"
        $cwd = "os.getcwd()"
        $dict_creation = /\{\s*['"]hostname['"]\s*:\s*\w+,\s*['"]cwd['"]\s*:\s*\w+,\s*['"]username['"]\s*:\s*\w+\s*\}/

    condition:
        all of ($hostname, $username, $cwd) or $dict_creation
}