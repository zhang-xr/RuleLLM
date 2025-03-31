rule Suspicious_Python_Setup_Metadata {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious metadata in Python setup.py files, such as random strings for package name, author, and description."
        confidence = 85
        severity = 75
    strings:
        $random_name = /name\s*=\s*["'][a-zA-Z]{6,}["']/
        $random_author = /author\s*=\s*["'][a-zA-Z]{6,}["']/
        $random_description = /description\s*=\s*["'][a-zA-Z]{10,}["']/
    condition:
        all of them
}