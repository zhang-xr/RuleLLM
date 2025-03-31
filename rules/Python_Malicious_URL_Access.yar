rule Python_Malicious_URL_Access {
    meta:
        author = "RuleLLM"
        description = "Detects Python code accessing suspicious URLs during installation"
        confidence = 90
        severity = 80
    strings:
        $urlopen = "urllib.request.urlopen"
        $install_cmd = "cmdclass={'install'"
        $http = "https://" wide
    condition:
        all of them and filesize < 10KB
}