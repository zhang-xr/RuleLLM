rule Windows_VBScript_Persistence {
    meta:
        author = "RuleLLM"
        description = "Detects Python scripts creating VBScript files in Windows Start Menu for persistence"
        confidence = 95
        severity = 90

    strings:
        $vbs_creation = /os\.(open|write)\(.*\\Start Menu\\Programs\\System86\\[^"]+\.vbs/
        $start_menu_path = /\\Start Menu\\Programs\\System86\\/
        $vbs_extension = ".vbs"

    condition:
        $vbs_creation and $start_menu_path and $vbs_extension
}