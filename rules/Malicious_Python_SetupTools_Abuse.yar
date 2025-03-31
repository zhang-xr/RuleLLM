rule Malicious_Python_SetupTools_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects malicious use of setuptools install hooks"
        confidence = 95
        severity = 90
    strings:
        $install_hook = "cmdclass={\"install\":"
        $sys_path = "sys.path.insert"
        $main_call = "main(b\"man\")"
        $setup_tools = "from setuptools import"
    condition:
        all of them and filesize < 10KB
}