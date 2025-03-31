rule Malicious_SystemInfo_Collection_Base64 {
    meta:
        author = "RuleLLM"
        description = "Detects Base64 encoded system information collection in Python scripts"
        confidence = "90"
        severity = "85"
    
    strings:
        $get_login = "doit(\"os\", \"getl\", \"ogin\")"
        $get_hostname = "doit(\"socket\", \"getho\", \"stbyname\")"
        $get_cwd = "doit(\"os\", \"getc\", \"wd\")"
        $base64_encode = "base64.urlsafe_b64encode"
        $base64_decode = "base64.b64decode"
    
    condition:
        all of them
}