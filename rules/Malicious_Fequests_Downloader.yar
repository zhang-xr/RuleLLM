rule Malicious_Fequests_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects malicious fequests package that downloads and executes binaries from remote server"
        confidence = "95"
        severity = "90"
    
    strings:
        $package_name = "fequests"
        $remote_url = "http://35.235.126.33/all.txt"
        $download_pattern = /requests\.get\('http:\/\/35\.235\.126\.33\/[^']+'\)/
        $exec_pattern1 = /os\.system\(f'\.\/{executable} &'\)/
        $exec_pattern2 = /os\.system\(f'start \/B {executable}'\)/
        $platform_check = "platform.system().lower()"
    
    condition:
        all of ($package_name, $remote_url) and 
        any of ($download_pattern, $exec_pattern1, $exec_pattern2) and 
        $platform_check
}