rule Python_Malicious_Package_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package setup script with custom install class"
        confidence = 85
        severity = 75
    strings:
        $setup_fn = "setup(name="
        $cmd_class = "cmdclass={'install':"
        $http_req = /requests\.get\([\s\S]*?\)/
    condition:
        $setup_fn and $cmd_class and $http_req
}