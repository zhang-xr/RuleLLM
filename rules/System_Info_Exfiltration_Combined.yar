rule System_Info_Exfiltration_Combined {
    meta:
        author = "RuleLLM"
        description = "Detects the combination of system info collection and HTTP requests for exfiltration"
        confidence = 95
        severity = 90
    strings:
        $hostname = "hostname=socket.gethostname()"
        $cwd = "cwd = os.getcwd()"
        $username = "username = getpass.getuser()"
        $requests_get = "requests.get("
        $params = "params = "
    condition:
        all of ($hostname, $cwd, $username) and any of ($requests_get, $params)
}