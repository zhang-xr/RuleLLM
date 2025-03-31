rule OAST_Domain_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects usage of OAST (Out-of-band Application Security Testing) domains for data exfiltration"
        confidence = "95"
        severity = "90"
    
    strings:
        $oast_domain1 = "dnipqouebm-psl.cn.oast-cn.byted-dast.com"
        $oast_domain2 = "oqvignkp58-psl.i18n.oast-row.byted-dast.com"
        $oast_domain3 = "sbfwstspuutiarcjzptf0rueg2x53eh2c.oast.fun"
        $urlencode = "urllib.parse.urlencode"
    
    condition:
        any of ($oast_domain*) and $urlencode
}