rule Malicious_Setup_Package {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python package installation patterns with post-install hooks"
        confidence = "90"
        severity = "85"
    strings:
        $post_install = "PostInstallScript(install)" ascii
        $cmd_class = "cmdclass={\"install\": PostInstallScript}" ascii
        $sys_path = "sys.path.insert(0, 'src')" ascii
    condition:
        all of them
}