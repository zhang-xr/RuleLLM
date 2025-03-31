rule Suspicious_Startup_Folder_Manipulation {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to manipulate files in the Windows Startup folder."
        confidence = 90
        severity = 85
    strings:
        $startup_path = /C:\\Users\\.*\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup/
        $os_makedirs = "os.makedirs(newpath)"
        $os_rename = "os.rename(src_path, dst_path)"
    condition:
        all of them
}