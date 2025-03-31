rule Python_Custom_UserAgent_Download {
    meta:
        author = "RuleLLM"
        description = "Detects Python code using custom User-Agent strings to download files"
        confidence = 80
        severity = 70

    strings:
        $user_agent = "User-Agent"
        $download = "download"
        $http = /https?:\/\/[^\s]+/

    condition:
        all of ($user_agent, $download, $http)
}