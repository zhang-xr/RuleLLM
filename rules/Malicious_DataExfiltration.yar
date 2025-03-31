rule Malicious_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious data collection and exfiltration via HTTP request"
        confidence = "90"
        severity = "80"
    
    strings:
        $platform_node = "platform.node()"
        $platform_uname = "platform.uname()"
        $ifconfig_cmd = "os.popen(\"ifconfig|grep inet|grep -v inet6\")"
        $base64_encode = "base64.b64encode(d.encode())"
        $suspicious_request = /requests\.get\(\"http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\/v\/%s\"/
    
    condition:
        all of them and 
        #suspicious_request > 0
}