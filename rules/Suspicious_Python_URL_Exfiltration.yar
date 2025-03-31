rule Suspicious_Python_URL_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL patterns used for data exfiltration in Python code"
        confidence = 95
        severity = 90
    strings:
        $url1 = "http://dnipqouebm-psl.cn.oast-cn.byted-dast.com"
        $url2 = "http://oqvignkp58-psl.i18n.oast-row.byted-dast.com"
        $url3 = "http://sbfwstspuutiarcjzptfenn9u0dsxhjlu.oast.fun"
        $urllib = "urllib.request.urlopen"
        $params = "urllib.parse.urlencode"
    condition:
        2 of ($url*) and ($urllib or $params)
}