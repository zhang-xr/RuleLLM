rule DataExfiltration_Generic {
    meta:
        author = "RuleLLM"
        description = "Detects generic data exfiltration of account information including cookies, IP, and user details"
        confidence = 90
        severity = 85
    
    strings:
        $ip_address = "api.ipify.org"
        $webhook_post = "requests.post"
        $user_details = /(RobuxBalance|CreationDate|Account Age)/
    
    condition:
        all of them and 
        #webhook_post >= 1 and 
        filesize < 100KB
}