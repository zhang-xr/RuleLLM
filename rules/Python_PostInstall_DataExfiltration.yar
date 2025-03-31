rule Python_PostInstall_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that execute code post-installation and exfiltrate system data"
        confidence = 90
        severity = 80
    strings:
        $install_override = "cmdclass={'install':"
        $post_request = /conn\.request\(\s*"POST"/
        $system_info = /(platform\.system|socket\.gethostname|sys\.executable|sys\.prefix)/
        $json_dumps = "json.dumps"
        $http_connection = /http\.client\.HTTPS?Connection/
    condition:
        all of them and 
        filesize < 10KB
}