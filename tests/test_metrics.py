from atp.server.metrics import ServerMetrics


def test_initial_metrics():
    m = ServerMetrics()
    d = m.to_dict()
    assert d["messages"]["received"] == 0
    assert d["security"]["ats_pass"] == 0
    assert d["uptime"] >= 0


def test_record_ats():
    m = ServerMetrics()
    m.record_ats("PASS")
    m.record_ats("PASS")
    m.record_ats("FAIL")
    d = m.to_dict()
    assert d["security"]["ats_pass"] == 2
    assert d["security"]["ats_fail"] == 1


def test_record_atk():
    m = ServerMetrics()
    m.record_atk(True)
    m.record_atk(False)
    d = m.to_dict()
    assert d["security"]["atk_pass"] == 1
    assert d["security"]["atk_fail"] == 1


def test_record_messages():
    m = ServerMetrics()
    m.record_message_received()
    m.record_local_delivery()
    m.record_forwarded()
    m.record_delivery_success()
    m.record_delivery_failed()
    m.record_bounced()
    d = m.to_dict()
    assert d["messages"]["received"] == 1
    assert d["messages"]["delivered_local"] == 1
    assert d["messages"]["forwarded"] == 1
    assert d["messages"]["delivery_success"] == 1
    assert d["messages"]["delivery_failed"] == 1
    assert d["messages"]["bounced"] == 1


def test_replay_blocked():
    m = ServerMetrics()
    m.record_replay_blocked()
    m.record_replay_blocked()
    d = m.to_dict()
    assert d["security"]["replay_blocked"] == 2
