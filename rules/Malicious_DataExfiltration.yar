rule Malicious_DataExfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code that collects system information and exfiltrates it to a remote server"
        confidence = "90"
        severity = "80"
    strings:
        $ip_collection = /socket\.socket\(socket\.AF_INET, socket\.SOCK_DGRAM\)/
        $system_info = /os\.getlogin|platform\.node|platform\.uname|os\.getcwd/
        $base64_encode = /base64\.b64encode\(.+\)/
        $remote_request = /requests\.get\(["']http:\/\/.+["']\)/
    condition:
        all of them
}