rule Python_DataExfiltration_SuspiciousURLs {
    meta:
        author = "RuleLLM"
        description = "Detects Python code with suspicious URLs and data exfiltration patterns"
        confidence = 90
        severity = 80
    strings:
        $url1 = "http://dnipqouebm-psl.cn.oast-cn.byted-dast.com001"
        $url2 = "http://oqvignkp58-psl.i18n.oast-row.byted-dast.com"
        $url3 = "http://sbfwstspuutiarcjzptf0rueg2x53eh2c.oast.fun"
        $hostname = "platform.node()"
        $username = "getpass.getuser()"
        $current_path = "os.getcwd()"
        $urlencode = "urllib.parse.urlencode"
        $urlopen = "urllib.request.urlopen"
    condition:
        (2 of ($url1, $url2, $url3)) and
        (2 of ($hostname, $username, $current_path)) and
        (1 of ($urlencode, $urlopen))
}