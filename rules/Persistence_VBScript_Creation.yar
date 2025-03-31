rule Persistence_VBScript_Creation {
    meta:
        author = "RuleLLM"
        description = "Detects the creation of a VBScript file for persistence on Windows"
        confidence = 95
        severity = 85

    strings:
        $vbs_creation = /with open\(.*\.vbs.*\)/
        $vbs_content = /CreateObject\(\"WScript\.Shell\"\)/
        $vbs_run = /\.Run/

    condition:
        all of them
}