rule Python_MaliciousPackage_Network {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages making suspicious network requests during installation"
        confidence = 85
        severity = 75
    strings:
        $requests_get = "requests.get"
        $oastify_domain = /[\'\"].+?\.oastify\.com[\'\"]/
        $params_keyword = "params"
        $system_info = /(hostname|username|cwd)/
    condition:
        $requests_get and 
        $oastify_domain and 
        $params_keyword and 
        $system_info
}