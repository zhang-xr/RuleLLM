rule Malicious_Python_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that collects system information and exfiltrates it via HTTP"
        confidence = "90"
        severity = "80"
    
    strings:
        $ip_collection = /socket\.socket\(socket\.AF_INET,\s*socket\.SOCK_DGRAM\)/
        $system_info = /platform\.(node|uname)\(\)/
        $base64_encode = /base64\.b64encode\(.*\.encode\(\)\)\.decode\('utf-8'\)/
        $http_exfil = /requests\.get\("http:\/\/[^"]+"/
        $setup_pkg = /setup\(.*name\s*=\s*"[^"]+"/
    
    condition:
        all of them and filesize < 10KB
}