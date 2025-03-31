rule Python_SystemInfo_Collection {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting system information including IP, hostname, and directories"
        confidence = 85
        severity = 70
    strings:
        $ipify = "api.ipify.org" ascii wide
        $uname = "os.uname()" ascii wide
        $expanduser = "os.expanduser" ascii wide
        $getcwd = "os.getcwd()" ascii wide
        $datetime = "datetime.now()" ascii wide
    condition:
        3 of ($ipify, $uname, $expanduser, $getcwd, $datetime)
}