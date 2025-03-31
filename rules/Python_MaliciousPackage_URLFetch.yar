rule Python_MaliciousPackage_URLFetch {
    meta:
        author = "RuleLLM"
        description = "Detects Python packages that fetch URLs during installation by overriding the install command."
        confidence = 90
        severity = 80

    strings:
        $urlopen = "urllib.request.urlopen"
        $install_override = "cmdclass={'install'"
        $post_install = "PostInstallCommand"

    condition:
        all of them and filesize < 10KB
}