rule Python_Web_Request_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python code making web requests to download files"
        confidence = 90
        severity = 85
    strings:
        $web = "WebRequest" ascii wide
        $invoke = "Invoke-Expression" ascii wide
        $outfile = "OutFile" ascii wide
        $http = /https?:\/\/[^\s"]+/ ascii wide
    condition:
        any of ($web, $invoke, $outfile) and
        $http and
        filesize < 10KB
}