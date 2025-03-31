rule Sensitive_Data_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects the collection of sensitive system information in Python scripts"
        confidence = 80
        severity = 70
    strings:
        $hostname = "socket.gethostname()"
        $cwd = "os.getcwd()"
        $username = "getpass.getuser()"
    condition:
        all of ($hostname, $cwd, $username)
}