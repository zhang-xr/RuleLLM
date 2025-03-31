rule SystemInfo_Collection_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information and sends it to a remote server"
        confidence = 90
        severity = 80
    strings:
        $ip_lookup = "api.ipify.org"
        $system_info = /(publicIP|hostname|homeDirectory|currentDirectory|currentTime)/
        $url_encode = "urlencode"
        $remote_server = /http:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}:\d+\//
        $urllib_import = "from urllib.request import urlopen, Request"
    condition:
        all of them
}