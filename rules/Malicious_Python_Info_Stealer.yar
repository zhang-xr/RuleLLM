rule Malicious_Python_Info_Stealer {
    meta:
        author = "RuleLLM"
        description = "Detects Python information stealing patterns with specific package names"
        confidence = 85
        severity = 75
    strings:
        $package_name = /PACKAGE_NAME\s*=\s*"[a-z0-9]{20,}"/
        $data_dict = /data\s*=\s*{.*"package_name".*}/
        $requests_post = "requests.post"
    condition:
        $package_name and 
        $data_dict and 
        $requests_post
}