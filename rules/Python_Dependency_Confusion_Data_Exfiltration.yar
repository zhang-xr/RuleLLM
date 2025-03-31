rule Python_Dependency_Confusion_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that collect sensitive system information and exfiltrate it to a remote server."
        confidence = 90
        severity = 80
    strings:
        $hostname = "socket.gethostname()"
        $cwd = "os.getcwd()"
        $username = "getpass.getuser()"
        $requests_get = "requests.get("
        $http_url = /https?:\/\/[a-zA-Z0-9\-\.]+\.[a-zA-Z]{2,}/
        $params = "params="
    condition:
        all of ($hostname, $cwd, $username) and 
        ($requests_get and $http_url and $params) and
        filesize < 10KB
}