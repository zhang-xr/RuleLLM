rule Python_SetupMasking {
    meta:
        author = "RuleLLM"
        description = "Detects malicious Python setup scripts using legitimate metadata"
        confidence = 80
        severity = 85

    strings:
        $setup = "from setuptools import setup"
        $license = "license='MIT'"
        $classifiers = "classifiers=['Development Status :: 5 - Production/Stable']"
        $exec_pattern = /(exec|_ssystem|_eexecutable)/

    condition:
        $setup and $license and $classifiers and $exec_pattern
}