rule Suspicious_Data_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious URL patterns and data exfiltration behavior"
        confidence = 95
        severity = 90

    strings:
        $url1 = "http://dnipqouebm-psl.cn.oast-cn.byted-dast.com"
        $url2 = "http://oqvignkp58-psl.i18n.oast-row.byted-dast.com"
        $url3 = "http://sbfwstspuutiarcjzptf3c0cvb6yng6mw.oast.fun"
        $params = "hostname" nocase
        $params2 = "username" nocase
        $params3 = "mac_address" nocase
        $base64 = "base64.b64encode("

    condition:
        (2 of ($url*)) and ($params and $params2 and $params3) and $base64
}