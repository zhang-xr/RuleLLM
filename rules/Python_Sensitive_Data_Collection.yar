rule Python_Sensitive_Data_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting sensitive system information"
        confidence = 95
        severity = 85
    strings:
        $hostname_collect = "socket.gethostname()"
        $username_collect = "getpass.getuser()"
        $cwd_collect = "os.getcwd()"
    condition:
        2 of ($hostname_collect, $username_collect, $cwd_collect)
}