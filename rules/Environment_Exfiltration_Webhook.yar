rule Environment_Exfiltration_Webhook {
    meta:
        author = "RuleLLM"
        description = "Detects exfiltration of environment variables to a remote webhook"
        confidence = 95
        severity = 90
    strings:
        $os_environ = "os.environ"
        $urlencode = "urllib.parse.urlencode"
        $urlopen = "urllib.request.urlopen"
        $webhook_url = /https?:\/\/[^\s"]+/ 
    condition:
        $os_environ and $urlencode and $urlopen and $webhook_url
}