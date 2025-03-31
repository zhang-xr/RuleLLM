rule Remote_Binary_Download {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of downloading and executing remote binaries"
        confidence = 95
        severity = 100
    strings:
        $http_get = "requests.get("
        $wb_write = "wb') as f:"
        $url_format = "http://{IP}/{executable}"
        $executable_var = "executable"
    condition:
        all of ($http_get, $wb_write) and 
        1 of ($executable_var, $url_format)
}