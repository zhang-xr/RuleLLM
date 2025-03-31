rule Suspicious_Python_Package_Obfuscation_System_Interaction {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with obfuscation and system interaction capabilities"
        confidence = 90
        severity = 85

    strings:
        $s1 = "import random ,base64,codecs,zlib" ascii wide
        $s2 = "pyobfuscate=" ascii wide
        $s3 = "winregistry" ascii wide
        $s4 = "pyautogui" ascii wide
        $s5 = "getmac" ascii wide

    condition:
        all of ($s1, $s2) and
        2 of ($s3, $s4, $s5)
}