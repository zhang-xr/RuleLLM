rule Python_DataExfiltration_InstallHook {
    meta:
        author = "RuleLLM"
        description = "Detects Python package with malicious installation hook and data exfiltration"
        confidence = 90
        severity = 85
    strings:
        $install_hook = "cmdclass={'install':"
        $urlopen = "urllib.request.urlopen"
        $platform = "platform.node()"
        $getuser = "getpass.getuser()"
        $random_url = /http:\/\/[a-z0-9\-]{10,}\.(cn|com|fun)/
        $params = /"hostname":\s*hostname,\s*"username":\s*username/
    condition:
        all of ($install_hook, $urlopen) and 
        2 of ($platform, $getuser, $random_url, $params)
}