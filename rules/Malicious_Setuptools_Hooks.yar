rule Malicious_Setuptools_Hooks {
    meta:
        author = "RuleLLM"
        description = "Detects malicious overrides of setuptools commands to execute code during installation or development."
        confidence = 85
        severity = 75

    strings:
        $develop_hook = "class PostDevelopCommand(develop)"
        $install_hook = "class PostInstallCommand(install)"
        $execute_call = "execute()"

    condition:
        all of ($develop_hook, $install_hook) and $execute_call
}