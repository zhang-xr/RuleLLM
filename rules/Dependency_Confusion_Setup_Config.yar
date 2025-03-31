rule Dependency_Confusion_Setup_Config {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup configuration for dependency confusion"
        confidence = 85
        severity = 80
    strings:
        $s1 = "setup(name='dependency_confusion"
        $s2 = "cmdclass={'install': CustomInstall}"
        $s3 = "description=\"This package is a proof of concept"
        $s4 = "version='9.9.9'"
    condition:
        3 of them
}