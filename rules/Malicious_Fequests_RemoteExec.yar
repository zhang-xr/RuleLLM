rule Malicious_Fequests_RemoteExec {
    meta:
        author = "RuleLLM"
        description = "Detects malicious 'fequests' package with remote code execution functionality"
        confidence = 95
        severity = 90
    strings:
        $ip_address = "35.235.126.33"
        $executable_download = /http:\/\/35\.235\.126\.33\/[a-zA-Z0-9_\-\.]+/
        $os_check = /platform\.system\(\)\.lower\(\)/
        $execution_linux = /os\.system\(\"\.\/[a-zA-Z0-9_\-\.]+\s\&\"\)/
        $execution_windows = /os\.system\(\"start\s\/B\s[a-zA-Z0-9_\-\.]+\"\)/
        $package_name = "fequests"
    condition:
        all of ($ip_address, $os_check) and 
        (1 of ($executable_download, $execution_linux, $execution_windows)) and 
        $package_name
}