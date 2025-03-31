rule Malicious_String_Constants {
    meta:
        author = "RuleLLM"
        description = "Detects specific malicious string constants used in the script"
        confidence = 80
        severity = 70
    strings:
        $str1 = "railroad" ascii wide
        $str2 = "jewel" ascii wide
        $str3 = "drown" ascii wide
        $str4 = "archive" ascii wide
    condition:
        2 of them and 
        filesize < 10KB
}