rule Malicious_Requests_Library {
    meta:
        author = "RuleLLM"
        description = "Detects malicious version of Python requests library that downloads and executes remote binaries"
        confidence = 90
        severity = 95
    strings:
        $ip = "35.235.126.33"
        $all_txt = "all.txt"
        $execute_func = "def execute():"
        $os_system = "os.system("
        $chmod = "chmod +x"
        $start_b = "start /B"
        $platform_system = "platform.system().lower()"
    condition:
        all of them and 
        filesize < 100KB
}