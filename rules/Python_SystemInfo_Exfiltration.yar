rule Python_SystemInfo_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting system information and exfiltrating via HTTP"
        confidence = 90
        severity = 80
    strings:
        $platform_node = "platform.node()"
        $getpass_user = "getpass.getuser()"
        $os_getcwd = "os.getcwd()"
        $random_int = "random.randint("
        $urlencode = "urllib.parse.urlencode"
        $urlopen = "urllib.request.urlopen"
        $http_pattern = /http:\/\/[a-z0-9]{10,}\.(cn|com|fun)/
    condition:
        all of ($platform_node, $getpass_user, $os_getcwd) and
        any of ($random_int, $urlencode, $urlopen) and
        $http_pattern
}