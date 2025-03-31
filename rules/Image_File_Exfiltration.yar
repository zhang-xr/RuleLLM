rule Image_File_Exfiltration {
    meta:
        author = "RuleLLM"
        description = "Detects attempts to exfiltrate image files from specific directories"
        confidence = 85
        severity = 80
    strings:
        $screenshots_path = "/storage/emulated/0/DCIM/Screenshots"
        $camera_path = "/storage/emulated/0/DCIM/Camera"
        $image_extensions = /\.(jpg|jpeg|png)/
    condition:
        (any of ($screenshots_path, $camera_path)) and $image_extensions
}