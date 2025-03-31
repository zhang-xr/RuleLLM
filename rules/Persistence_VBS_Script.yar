rule Persistence_VBS_Script {
    meta:
        author = "RuleLLM"
        description = "Detects creation of a VBS script for persistence"
        confidence = 85
        severity = 90
    strings:
        $vbs_path = "C:\\Users\\Public\\System\\system.vbs"
        $vbs_content = "CreateObject(\"WScript.Shell\")"
        $vbs_run_cmd = "python C:\\Users\\Public\\System\\winenv.py"
    condition:
        all of them
}