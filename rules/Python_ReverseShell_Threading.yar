rule Python_ReverseShell_Threading {
    meta:
        author = "RuleLLM"
        description = "Detects the use of threading for reverse shell communication"
        confidence = 80
        severity = 85

    strings:
        // Threading for input/output redirection
        $threading = /threading\.Thread\([\s\S]*?target=[\s\S]*?args=/
        $stdin_write = /stdin\.write\([\s\S]*?\)/
        $stdout_read = /stdout\.read\([\s\S]*?\)/

    condition:
        // Match if threading is used with stdin/stdout operations
        $threading and ($stdin_write or $stdout_read)
}