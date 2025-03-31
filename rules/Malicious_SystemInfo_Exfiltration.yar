rule Malicious_SystemInfo_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects collection and exfiltration of system information via HTTP requests"
        confidence = 90
        severity = 85

    strings:
        $getmac = "getmac" ascii
        $ifconfig = "ifconfig" ascii
        $hostname = "pltfrm.node()" ascii
        $username = "gtps.getuser()" ascii
        $mac_address = "g_m_a()" ascii
        $urlopen = "urqt.urlopen" ascii
        $urlencode = "uprs.urlencode" ascii
        $b64encode = "b64.b64encode" ascii

    condition:
        all of ($getmac, $ifconfig, $hostname, $username, $mac_address) and 
        any of ($urlopen, $urlencode, $b64encode)
}