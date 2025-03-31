rule Malicious_File_Download_Pattern {
    meta:
        author = "RuleLLM"
        description = "Detects patterns of file downloads to current working directory with executable extensions"
        confidence = 90
        severity = 80
        reference = "Analyzed code segment"
    
    strings:
        $os_path = "os.path.join(os.getcwd(),"
        $exe_ext = /\.[eE][xX][eE]"/
        $curl_cmd = "curl.exe"
        $output_flag = "-o"
    
    condition:
        $os_path and 
        $exe_ext and 
        ($curl_cmd or $output_flag)
}