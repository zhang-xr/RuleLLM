rule Malicious_Python_SystemInfoCollection_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code collecting system information and exfiltrating it"
        confidence = 90
        severity = 85
    strings:
        $hostname = "platform.node()"
        $username = "getpass.getuser()"
        $current_path = "os.getcwd()"
        $urlencode = "urllib.parse.urlencode"
        $urlopen = "urllib.request.urlopen"
    condition:
        all of ($hostname, $username, $current_path) and any of ($urlencode, $urlopen)
}