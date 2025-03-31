rule Dependency_Confusion_Attack {
    meta:
        author = "RuleLLM"
        description = "Detects dependency confusion attacks with data exfiltration"
        confidence = 95
        severity = 95
    strings:
        $setup_import = "from setuptools import setup"
        $install_import = "from setuptools.command.install import install"
        $http_get = "requests.get("
        $sensitive_data = /(hostname|cwd|username)/
        $domain_pattern = /https?:\/\/[a-z0-9]{16,}\.[a-z]{2,}/
    condition:
        3 of them and
        filesize < 10KB
}