rule Python_Suspicious_URL_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code executing content from remote URLs"
        confidence = "92"
        severity = "88"
    
    strings:
        $urlopen = "urlopen("
        $exec_pattern = /exec\([^\)]+\)/
        $http_pattern = /http:\/\/[^\s]+/
        $remote_exec = /exec\(.*\.read\(\)\)/
    
    condition:
        all of them and 
        filesize < 10KB
}