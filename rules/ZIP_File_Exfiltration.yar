rule ZIP_File_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects code creating ZIP files for data exfiltration"
        confidence = 85
        severity = 90

    strings:
        $zipfile = "ZipFile" ascii wide
        $write_method = "write(" ascii wide
        $remove_method = "os.remove(" ascii wide

    condition:
        all of ($zipfile, $write_method) and 
        $remove_method
}