rule Suspicious_External_Connections {
    meta:
        author = "RuleLLM"
        description = "Detects connections to suspicious external domains"
        confidence = 85
        severity = 95
    strings:
        $url1 = "dnipqouebm-psl.cn.oast-cn.byted-dast.com"
        $url2 = "oqvignkp58-psl.i18n.oast-row.byted-dast.com"
        $url3 = "sbfwstspuutiarcjzptfenn9u0dsxhjlu.oast.fun"
    condition:
        any of them
}