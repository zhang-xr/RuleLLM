rule Data_Exfiltration_via_HTTP_GET {
    meta:
        author = "RuleLLM"
        description = "Detects HTTP GET requests used for data exfiltration, particularly with system information collection"
        confidence = 90
        severity = 85
    strings:
        $urlopen1 = "urlopen("
        $urlopen2 = "urllib.request.urlopen"
        $urlencode = "urlencode"
        $system_info = /(publicIP|hostname|homeDirectory|currentDirectory|currentTime)/
        $http_request = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\//
    condition:
        all of ($urlopen*) and 
        $urlencode and 
        $system_info and 
        $http_request
}