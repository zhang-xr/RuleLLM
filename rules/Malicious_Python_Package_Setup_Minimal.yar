rule Malicious_Python_Package_Setup_Minimal {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious Python package setup with minimal metadata and empty fields"
        confidence = 80
        severity = 70
    strings:
        $setup_name = "name=\"mumuziyyds\"" ascii
        $empty_url = "url=\"\"" ascii
        $empty_email = "author_email=\"\"" ascii
        $test_description = "description=\"for test\"" ascii
    condition:
        all of them
}