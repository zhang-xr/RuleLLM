rule Remote_Code_Execution_URL {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that fetches and executes code from a remote URL"
        confidence = 90
        severity = 95

    strings:
        $urlopen = "urlopen"
        $exec = "exec"
        $http = /https?:\/\/[^\s]+/ 
        $write = "write"

    condition:
        all of ($urlopen, $exec, $http) and $write
}