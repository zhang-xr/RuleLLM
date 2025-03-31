rule Python_SuspiciousPostInstall {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious post-installation behavior in Python packages"
        confidence = 85
        severity = 75
    strings:
        $post_install = "_post_install():"
        $file_write = /open\s*\(.+,\s*[\"']a\+[\"']\)/
        $system_info = /os\.uname\(\)|pathlib\.Path\(__file__\)\.parent\.absolute\(\)/
        $data_construction = /\{[^}]+\"ip\"\s*:/
    condition:
        3 of them
}