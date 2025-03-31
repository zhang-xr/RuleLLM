rule System_Reconnaissance {
    meta:
        author = "RuleLLM"
        description = "Detects system reconnaissance activities including process and directory enumeration"
        confidence = "85"
        severity = "80"
    strings:
        $proc_access = "/proc/" ascii
        $cwd_walk = "walk_cwd()" ascii
        $git_config = "git config user.email" ascii
        $subprocess = "subprocess.run" ascii
    condition:
        3 of them
}