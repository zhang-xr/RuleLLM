rule Python_TypoSquatting_Setup {
    meta:
        author = "RuleLLM"
        description = "Detects potential typo-squatting in Python package setup"
        confidence = 90
        severity = 80
    strings:
        $setup = "setup("
        $typo_desc = /description\s*=\s*['\"].*typo.*['\"]/
        $generic_name = /name\s*=\s*['\"][a-z]+[0-9]+['\"]/
    condition:
        filesize < 10KB and
        all of them
}