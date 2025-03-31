rule Suspicious_Python_Setup_Attributes {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious attributes in Python setup.py files"
        confidence = "85"
        severity = "75"
    
    strings:
        $cmdclass = "cmdclass={'install':"
        $empty_description = "description = ':clown:'"
        $empty_author = "author = ':clown:'"
    
    condition:
        any of them and filesize < 10KB
}