rule Python_Download_Executable {
    meta:
        author = "RuleLLM"
        description = "Detects Python code downloading and potentially executing external executables"
        confidence = 85
        severity = 85
    strings:
        $url = /https?:\/\/[^"]+\.exe/
        $subprocess = "subprocess"
        $file_ops = /(open|write|close)\(/
    condition:
        any of ($url, $subprocess) and $file_ops
}