rule Python_Base64_Hostname_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects base64 encoded hostname exfiltration in Python code"
        confidence = "95"
        severity = "85"
    
    strings:
        $base64_encode = "base64.b64encode"
        $socket_fqdn = "socket.getfqdn"
        $url_construction = /https?:\/\/[^\s]+\?[a-zA-Z0-9=]+/
    
    condition:
        all of them and
        #base64_encode < 3 and
        #socket_fqdn < 3
}