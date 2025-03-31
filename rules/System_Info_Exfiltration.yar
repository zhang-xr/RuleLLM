rule System_Info_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information (hostname, cwd, username) and exfiltrates it via HTTP requests"
        confidence = 95
        severity = 90
    strings:
        $hostname = "hostname=socket.gethostname()"
        $cwd = "cwd = os.getcwd()"
        $username = "username = getpass.getuser()"
        $requests_get = "requests.get("
        $params = "params = "
    condition:
        all of ($hostname, $cwd, $username, $requests_get, $params)
}