rule Suspicious_Setup_Install_Script {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setup.py install script"
        confidence = 95
        severity = 90

    strings:
        $post_install_script = "class PostInstallScript"
        $cmdclass_install = "cmdclass={\"install\": PostInstallScript}"
        $sys_path_insert = "sys.path.insert"
        $main_call = "main(b\"man3\")"

    condition:
        all of ($post_install_script, $cmdclass_install, $sys_path_insert, $main_call)
}