rule Malicious_Python_Post_Install_Hook {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that uses post-install or post-develop hooks to execute malicious code"
        confidence = "85"
        severity = "75"

    strings:
        $develop_hook = "class PostDevelopCommand(develop)"
        $install_hook = "class PostInstallCommand(install)"
        $execute_function = "def execute():"

    condition:
        all of them
}