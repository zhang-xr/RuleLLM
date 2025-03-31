rule Python_RemoteCodeExecution_urllib {
    meta:
        author = "RuleLLM"
        description = "Detects Python code downloading and executing remote content using urllib.request"
        confidence = 90
        severity = 80

    strings:
        $urllib_request = "from urllib.request import Request, urlopen"
        $exec_pattern = /exec\(urlopen\(.*?\)\.read\(\)\)/
        $http_url = /https?:\/\/[^\s]+/ ascii wide

    condition:
        all of them and filesize < 10KB
}