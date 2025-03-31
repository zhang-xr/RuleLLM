rule Python_RemoteCodeExecution_URLDownload {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that download and execute code from a remote URL using urllib.request.urlopen"
        confidence = 90
        severity = 95

    strings:
        $urlopen = "urlopen" ascii
        $exec = "exec(" ascii
        $urllib = "urllib.request" ascii
        $http = /https?:\/\/[^\s]+/ ascii

    condition:
        all of ($urlopen, $exec, $urllib) and 1 of ($http)
}