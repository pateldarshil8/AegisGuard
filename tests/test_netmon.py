from aegisguard.modules.netmon import Conn, analyze


def conn(**kw):
    base = dict(pid=1, proc="p.exe", exe=r"C:\Program Files\App\p.exe", status="ESTABLISHED",
                laddr_ip="192.168.1.5", laddr_port=50000, raddr_ip="8.8.8.8", raddr_port=443)
    base.update(kw)
    return Conn(**base)


def titles(res):
    return [f.title for f in res.findings]


def test_normal_traffic_is_clean():
    assert analyze([conn()]).findings == []


def test_risky_listener_flagged_once():
    c = conn(status="LISTEN", laddr_ip="0.0.0.0", laddr_port=3389, raddr_ip=None, raddr_port=None)
    res = analyze([c, c])
    assert len(res.findings) == 1 and "RDP" in res.findings[0].title


def test_listener_on_loopback_ignored():
    c = conn(status="LISTEN", laddr_ip="127.0.0.1", laddr_port=3389, raddr_ip=None, raddr_port=None)
    assert analyze([c]).findings == []


def test_temp_program_to_internet_is_high():
    c = conn(exe=r"C:\Users\a\AppData\Local\Temp\x.exe")
    res = analyze([c])
    assert res.findings[0].severity.value == "high"


def test_private_destination_not_flagged():
    c = conn(exe=r"C:\Users\a\Downloads\x.exe", raddr_ip="192.168.1.9")
    assert analyze([c]).findings == []


def test_unusual_port_flagged():
    assert any("4444" in t for t in titles(analyze([conn(raddr_port=4444)])))
