rule Malicious_Git_Clone_Operation {
    meta:
        author = "RuleLLM"
        description = "Detects Git clone operations in potentially malicious contexts."
        confidence = 85
        severity = 80
    strings:
        $git_clone = "git.Git(repoDirectory).clone(gitUrl)"
        $git_url = "gitUrl = \"https://github.com/"
    condition:
        all of them
}