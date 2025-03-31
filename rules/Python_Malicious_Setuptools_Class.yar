rule Python_Malicious_Setuptools_Class {
    meta:
        author = "RuleLLM"
        description = "Detects malicious setuptools installation classes overriding the run method"
        confidence = 80
        severity = 85

    strings:
        $setuptools_import = "from setuptools.command.install import install"
        $class_definition = /class\s+\w+\(install\):/
        $run_method = /def\s+run\(self\):/

    condition:
        $setuptools_import and
        $class_definition and
        $run_method
}