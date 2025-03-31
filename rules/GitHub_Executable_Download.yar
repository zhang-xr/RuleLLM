rule GitHub_Executable_Download {
    meta:
        author = "RuleLLM"
        description = "Detects executable download from GitHub repositories"
        confidence = 85
        severity = 80
    strings:
        $github_domain = "github.com"
        $exe_extension = /\.exe"/
        $curl_command = /curl\.exe\s+-L\s+https:\/\/[^\s]+\/[^\s]+\.exe/
    condition:
        all of them and 
        #github_domain < 10 and 
        #exe_extension < 5
}