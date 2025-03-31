rule Malicious_Python_Post_Install_Hooks {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts overriding post-install or post-develop hooks for malicious purposes"
        confidence = 85
        severity = 75

    strings:
        $post_install_hook = /cmdclass\s*=\s*{[\s\S]*'install'\s*:\s*[\w\.]+}/
        $post_develop_hook = /cmdclass\s*=\s*{[\s\S]*'develop'\s*:\s*[\w\.]+}/
        $exec_pattern = /execute\(\)/

    condition:
        ($post_install_hook or $post_develop_hook) and $exec_pattern
}