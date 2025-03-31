rule MaliciousPythonPackage_PostInstallHook {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages using post-install hooks for malicious activities"
        confidence = 85
        severity = 75
    strings:
        $setup_tools = "from setuptools import setup"
        $post_install = "class PostInstallCommand"
        $cmd_class = "cmdclass={'install'"
    condition:
        all of them
}