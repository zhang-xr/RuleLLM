rule Persistence_VBS_Script {
    meta:
        author = "RuleLLM"
        description = "Detects creation of a VBS script for persistence on Windows systems."
        confidence = 85
        severity = 80

    strings:
        $vbs_script = /CreateObject\(\"WScript\.Shell\"\)/
        $vbs_run = /\.Run/
        $system_vbs_path = "C:\\Users\\Public\\System\\system.vbs"
        $winenv_py_path = "C:\\Users\\Public\\System\\winenv.py"

    condition:
        all of them
}