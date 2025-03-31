rule Python_Package_EnvVar_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that exfiltrate environment variables during installation/development"
        confidence = 95
        severity = 90
    strings:
        $install_hook = "class AfterInstall(install):"
        $develop_hook = "class AfterDevelop(develop):"
        $env_collect = "data = dict(os.environ)"
        $url_encode = "urllib.parse.urlencode(data).encode()"
        $url_open = "urllib.request.urlopen(req)"
        $ngrok_url = /https:\/\/[a-z0-9]{12}\.ngrok\.app\/collect/
    condition:
        any of ($install_hook, $develop_hook) and 
        all of ($env_collect, $url_encode, $url_open) and 
        $ngrok_url
}