rule Python_Malicious_Setup_Structure {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious structure in Python setup files"
        confidence = 80
        severity = 70
    strings:
        $setup_import = "from setuptools import setup"
        $find_packages = "find_packages"
        $url_field = "url="
        $email_field = "author_email="
    condition:
        filesize < 2KB and
        all of them and
        #setup_import == 1 and
        #find_packages == 1 and
        #url_field == 1 and
        #email_field == 1
}