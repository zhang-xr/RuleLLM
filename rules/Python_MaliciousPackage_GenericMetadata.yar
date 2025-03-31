rule Python_MaliciousPackage_GenericMetadata {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages with generic metadata that could indicate malicious intent."
        confidence = 80
        severity = 70

    strings:
        $generic_name = /name\s*=\s*['"][a-z0-9]{1,5}['"]/
        $generic_desc = /description\s*=\s*['"](Security|PoC|Test|Example)/
        $author_email = /author_email\s*=\s*['"].*@.*\.com['"]/

    condition:
        all of them and filesize < 10KB
}