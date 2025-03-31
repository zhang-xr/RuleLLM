rule Malicious_Python_File_Deletion_After_Execution {
    meta:
        author = "RuleLLM"
        description = "Detects Python code that deletes a file after execution"
        confidence = 88
        severity = 85

    strings:
        $os_remove = /os\.remove\(/ nocase
        $exec = /exec\(/ nocase

    condition:
        $os_remove and $exec
}