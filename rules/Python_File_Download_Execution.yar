rule Python_File_Download_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects file download and execution patterns in Python scripts"
        confidence = 95
        severity = 90
    strings:
        $http_get = "get('http"
        $file_write = /open\(.*,\s*['"]w['"]/
        $file_execute = /call\(.*\.exe/
    condition:
        all of them
}