rule Suspicious_Python_URL_Fetch_Exec {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that fetches and executes code from a URL."
        confidence = 95
        severity = 100

    strings:
        $urlopen = "from urllib.request import urlopen as _uurlopen"
        $exec = "exec(_uurlopen"
        $http = "http://" nocase
        $https = "https://" nocase

    condition:
        all of ($urlopen, $exec) and 
        (1 of ($http, $https))
}