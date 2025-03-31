rule Malicious_Python_Setup_Download_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setup.py files that download and execute payloads from external URLs"
        confidence = 90
        severity = 85
    
    strings:
        $url_pattern = /https?:\/\/[^\s]+\.(exe|dll|bat|cmd)/ nocase
        $download_pattern = "requests.get"
        $execute_pattern = "os.system"
        $setup_pattern = "setup("
        $cmdclass_pattern = "cmdclass"
    
    condition:
        all of ($setup_pattern, $cmdclass_pattern, $download_pattern, $execute_pattern, $url_pattern)
}