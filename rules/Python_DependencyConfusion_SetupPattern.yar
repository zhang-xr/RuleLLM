rule Python_DependencyConfusion_SetupPattern {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious setup.py patterns for dependency confusion attacks"
        confidence = 85
        severity = 75
    strings:
        $setup_pattern = "setup(name="
        $cmdclass = "cmdclass={'install':"
        $suspicious_license = /license\s*=\s*['"]MIT['"]/
        $suspicious_version = /version\s*=\s*['"]\d+\.\d+\.\d+['"]/
        $disclaimer = "proof of concept"
    condition:
        3 of them and $cmdclass
}