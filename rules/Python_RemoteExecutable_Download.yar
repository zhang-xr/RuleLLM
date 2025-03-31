rule Python_RemoteExecutable_Download {
    meta:
        author = "RuleLLM"
        description = "Detects Python code downloading and executing remote executables"
        confidence = 95
        severity = 90
    strings:
        $requests_import = "import requests"
        $url_pattern = /https?:\/\/[^\s\"']+\.exe/
        $write_pattern = /open\([^,]+,\s*[\"']wb[\"']\)\.write\(/
        $exec_pattern = /start\s+\w+\.exe/
    condition:
        $requests_import and 
        $url_pattern and 
        $write_pattern and 
        $exec_pattern
}