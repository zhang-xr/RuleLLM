rule Python_Tmp_File_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects file creation in /tmp directory in Python scripts"
        confidence = 80
        severity = 60
    
    strings:
        $tmp_write = /with open\s*\([^\)]*\/tmp\/[^\)]+\) as \w+/
    
    condition:
        $tmp_write
}