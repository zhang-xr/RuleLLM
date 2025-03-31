rule Sensitive_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects sensitive system information and exfiltrates it"
        confidence = 90
        severity = 85

    strings:
        $hostname = "socket.gethostname()"
        $username = "getpass.getuser()"
        $cwd = "os.getcwd()"
        $http_request = "requests.get"
        $payload_dict = /\{\s*['\"]hostname['\"]\s*:\s*hostname\s*,\s*['\"]cwd['\"]\s*:\s*cwd\s*,\s*['\"]username['\"]\s*:\s*username\s*\}/

    condition:
        all of ($hostname, $username, $cwd, $http_request) and $payload_dict
}