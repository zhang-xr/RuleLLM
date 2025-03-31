rule Data_Exfiltration_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects data exfiltration setup including DNS and HTTP requests"
        confidence = 95
        severity = 90
    strings:
        $gethostbyname = "socket.gethostbyname"
        $urllib_request = "urllib.request.Request"
        $b64encode = "b64encode(data)"
        $ns_depcon = ".ns.depcon.buzz"
    condition:
        $gethostbyname and $urllib_request and $b64encode and $ns_depcon
}