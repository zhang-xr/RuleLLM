rule Hardcoded_IP_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects hardcoded IP addresses used for data exfiltration"
        confidence = "98"
        severity = "90"
    
    strings:
        $ip_address = /129\.226\.195\.123/
        $http_request = /requests\.get\("http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/
        $data_collection = /(os|platform)\.\w+\(\)/
    
    condition:
        $ip_address and $http_request and $data_collection
}