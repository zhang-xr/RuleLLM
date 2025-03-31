rule Suspicious_PostInstall_PackageInstallation {
    meta:
        author = "RuleLLM"
        description = "Detects suspicious installation of external packages during post-install phase in Python setup scripts"
        confidence = 85
        severity = 75

    strings:
        $pip_install = /call\(\[f".* -m pip install .*"\], shell=True\)/
        $post_install_func = "def _post_install(dir):"

    condition:
        filesize < 10KB and
        all of them
}