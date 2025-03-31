rule Malicious_Python_Package_Downloader {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that download and execute external executables"
        confidence = 90
        severity = 80
        
    strings:
        $url_pattern = /https?:\/\/[a-f0-9]{8}(-[a-f0-9]{4}){3}-[a-f0-9]{12}\.id\.repl\.co\/[^\/]+\.exe/
        $download_code = "requests.get("
        $write_file = "open("
        $execute_code = "os.system("
        
    condition:
        all of them and
        filesize < 10KB
}