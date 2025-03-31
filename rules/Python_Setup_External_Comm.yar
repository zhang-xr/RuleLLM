rule Python_Setup_External_Comm {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts making external communications during installation"
        confidence = "90"
        severity = "85"
    
    strings:
        $curl_cmd = "curl"
        $post_request = "curl -X POST"
        $setup_import = "from setuptools import setup"
        $os_system = "os.system"
        $cmd_class = /Custom\w+Command/
    
    condition:
        filesize < 20KB and
        $setup_import and
        ($os_system and $curl_cmd) and
        2 of ($post_request, $cmd_class)
}