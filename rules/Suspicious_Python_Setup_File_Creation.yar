rule Suspicious_Python_Setup_File_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts that create files during installation, potentially for malicious purposes."
        confidence = 85
        severity = 75

    strings:
        $setup_function = "setup("
        $cmdclass_keyword = "cmdclass"
        $file_write_pattern = /with\s+open\s*\([^)]+\)\s+as\s+\w+/
        $create_class = "class create()"

    condition:
        all of them and
        $setup_function and
        $cmdclass_keyword and
        $file_write_pattern and
        $create_class
}