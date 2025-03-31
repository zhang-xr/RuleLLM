rule Python_PostInstall_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious post-install hooks in Python setup scripts"
        confidence = 85
        severity = 75
    strings:
        $atexit = "atexit.register"
        $install_class = "class new_install(install)"
        $post_install = "_post_install"
        $setup_tools = "from setuptools import"
    condition:
        all of them and 
        filesize < 10KB
}