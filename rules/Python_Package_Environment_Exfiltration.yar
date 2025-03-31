rule Python_Package_Environment_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that exfiltrate environment variables during installation/development"
        confidence = 95
        severity = 90
    strings:
        $cmdclass1 = "cmdclass={'develop':"
        $cmdclass2 = "cmdclass={'install':"
        $urlencode = "urllib.parse.urlencode"
        $urlopen = "urllib.request.urlopen"
        $environ = "os.environ"
        $ngrok = /https:\/\/[a-z0-9]+\.ngrok\.(io|app|com|net)/
    condition:
        all of ($cmdclass*) and 
        ($urlencode or $urlopen) and 
        $environ and 
        $ngrok
}