rule Python_Exfil_Environment_Vars {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects and exfiltrates environment variables to a remote server"
        confidence = 90
        severity = 80
    strings:
        $collect_env = "os.environ" ascii
        $url_encode = "urllib.parse.urlencode" ascii
        $http_post = "urllib.request.Request" ascii
        $ngrok_url = /https?:\/\/[a-z0-9]{12}\.ngrok\.(io|app)/ ascii
        $custom_cmd = "cmdclass={" ascii
    condition:
        3 of them and $ngrok_url
}