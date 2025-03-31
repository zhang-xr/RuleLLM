rule Python_Setup_File_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects file creation patterns in Python setup scripts"
        confidence = 80
        severity = 75
    
    strings:
        $file_open = "open("
        $write_mode = /['"]w['"]/
        $write_call = ".write("
    
    condition:
        all of them and 
        filesize < 10KB
}