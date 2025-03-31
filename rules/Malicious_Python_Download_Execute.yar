rule Malicious_Python_Download_Execute {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that downloads and executes an external executable"
        confidence = "90"
        severity = "80"

    strings:
        $url_regex = /https?:\/\/[a-zA-Z0-9\-\.]+\.repl\.co\/[a-zA-Z0-9\-\.]+\.exe/
        $download_code = "requests.get"
        $execute_code = "os.system"
        $write_code = /open\(\"[a-zA-Z0-9\-\.]+\.exe\", \"wb\"\)\.write/

    condition:
        all of them
}