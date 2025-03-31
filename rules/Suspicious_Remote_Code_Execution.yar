rule Suspicious_Remote_Code_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects potential remote code execution through URL opening"
        confidence = 90
        severity = 85

    strings:
        $urlopen = "_uurlopen("
        $http = /['"]http:\/\/.*?['"]/
        $exec = "exec("

    condition:
        all of them and filesize < 10KB
}