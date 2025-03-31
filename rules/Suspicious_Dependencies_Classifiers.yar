rule Suspicious_Dependencies_Classifiers {
    meta:
        author = "RuleLLM"
        description = "Detects Python setup scripts with suspicious dependencies or classifiers, such as targeting only Windows OS."
        confidence = 80
        severity = 60

    strings:
        $suspicious_setup_requires = "setup_requires=['fernet', 'requests']"
        $windows_classifier = "\"Operating System :: Microsoft :: Windows\""

    condition:
        $suspicious_setup_requires and $windows_classifier
}