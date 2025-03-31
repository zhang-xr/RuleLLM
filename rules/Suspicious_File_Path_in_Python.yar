rule Suspicious_File_Path_in_Python {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts that create files in suspicious locations like /tmp."
        confidence = 80
        severity = 70

    strings:
        $tmp_path = "/tmp/"
        $file_write_pattern = /with\s+open\s*\([^)]+\)\s+as\s+\w+/

    condition:
        all of them and
        $tmp_path and
        $file_write_pattern
}