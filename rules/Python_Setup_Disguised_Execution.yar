rule Python_Setup_Disguised_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup files with execution patterns"
        confidence = "90"
        severity = "85"
    
    strings:
        $setup = "from setuptools import setup"
        $exec_pattern = /exec\(.*?read\(\)\)/
        $system_call = "system("
        $tempfile = "NamedTemporaryFile"
        $urlopen = "urlopen"
    
    condition:
        $setup and 
        ($exec_pattern or $system_call) and 
        ($tempfile or $urlopen) and 
        filesize < 15KB
}