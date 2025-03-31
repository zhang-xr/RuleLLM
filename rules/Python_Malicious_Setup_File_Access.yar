rule Python_Malicious_Setup_File_Access {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup files attempting to access sensitive system files"
        confidence = 90
        severity = 80
    strings:
        $file_access1 = /open\([^)]*\/etc\/passwd/
        $file_access2 = /open\([^)]*\.profile/
        $uid_check = "b[2] == str(1000)"
    condition:
        all of them
}