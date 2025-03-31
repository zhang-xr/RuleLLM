rule PyCrypter_Windows_Persistence {
    meta:
        author = "RuleLLM"
        description = "Detects Windows-specific persistence mechanisms in Python scripts"
        confidence = 90
        severity = 80
    strings:
        $system_path = "C:\\Users\\Public\\System"
        $vbs_script = "CreateObject(\"WScript.Shell\")"
        $vbs_run = "vOpcQrtacv.Run vcOpcaTAcOP,0"
        $subprocess_cmd = "cmd /c C:\\Users\\Public\\System\\system.vbs"
    condition:
        all of them
}