rule Python_SetupTools_Abuse {
    meta:
        author = "RuleLLM"
        description = "Detects abuse of setuptools install/develop commands for malicious execution"
        confidence = 85
        severity = 75
    strings:
        $s1 = "from setuptools.command.develop import develop" ascii wide
        $s2 = "from setuptools.command.install import install" ascii wide
        $s3 = /class Post(Develop|Install)Command\((develop|install)\)/ ascii wide
        $s4 = "def run(self):" ascii wide
        $s5 = "execute()" ascii wide
    condition:
        3 of them
}