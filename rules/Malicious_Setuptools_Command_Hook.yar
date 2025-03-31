rule Malicious_Setuptools_Command_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects malicious use of setuptools command hooks to exfiltrate environment variables"
        confidence = 90
        severity = 80
    strings:
        $cmdclass = "cmdclass"
        $develop = "develop"
        $install = "install"
        $webhook_url = /https?:\/\/[^\s"]+/ 
        $urlencode = "urllib.parse.urlencode"
        $urlopen = "urllib.request.urlopen"
    condition:
        all of ($cmdclass, $develop, $install) and 
        any of ($webhook_url, $urlencode, $urlopen)
}