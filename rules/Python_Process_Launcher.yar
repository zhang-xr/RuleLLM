rule Python_Process_Launcher {
    meta:
        author = "RuleLLM"
        description = "Detects the use of system to launch a Python process with a script"
        confidence = 85
        severity = 75

    strings:
        $system_import = "from os import system"
        $python_launch = /system\(f"start .*pythonw?\.exe.*"\)/

    condition:
        $system_import and $python_launch
}