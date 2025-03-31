rule System_Info_Collection_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects collection and exfiltration of system information via HTTP requests"
        confidence = 95
        severity = 90
    strings:
        $ipify = "api.ipify.org"
        $system_keys = /(hostname|homeDirectory|currentDirectory|currentTime)/
        $urlencode = "urlencode"
        $http_request = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\//
    condition:
        $ipify and 
        any of ($system_keys) and 
        $urlencode and 
        $http_request
}