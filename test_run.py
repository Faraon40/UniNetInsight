import io
import os
import sys
import pytest
import subprocess
import xml.etree.ElementTree as ETree

import run

# 4.1 validate_subnet
def test_validate_subnet_valid(monkeypatch):
    # should not raise
    run.validate_subnet("10.0.0.0/24")

def test_validate_subnet_invalid_exits(capsys):
    with pytest.raises(SystemExit):
        run.validate_subnet("not-a-subnet")
    captured = capsys.readerr()
    assert "invalid or missing" in captured.err

# 4.2 parse_nmap_xml
class DummyResult:
    def __init__(self, xml_str):
        self.stdout = xml_str

@pytest.fixture
def simple_nmap_xml():
    return """<?xml version="1.0"?>
    <nmaprun>
      <host>
        <status state="up"/>
        <address addr="192.168.1.1" addrtype="ipv4"/>
        <address addr="00:11:22:33:44:55" addrtype="mac" vendor="AcmeCo"/>
      </host>
      <host>
        <status state="down"/>
        <address addr="192.168.1.2" addrtype="ipv4"/>
      </host>
    </nmaprun>"""

def test_parse_nmap_xml_up_and_down_hosts(monkeypatch, simple_nmap_xml):
    # stub out DNS lookup to force predictable hostnames
    monkeypatch.setattr(run.socket, "gethostbyaddr",
                        lambda ip: ("host-"+ip, [], []))
    result = run.parse_nmap_xml(DummyResult(simple_nmap_xml))
    assert len(result) == 2

    up, down = result
    assert up["status"] == "active"
    assert up["mac_addr"] == "00:11:22:33:44:55"
    assert up["manufacturer"] == "AcmeCo"
    assert up["hostname"] == "host-192.168.1.1"

    assert down["status"] == "offline"
    assert down["mac_addr"] == ""
    assert down["manufacturer"] == "Unspecified"
    assert down["hostname"] is None

# 4.3 post_to: success and failure
def make_response(status_code, json_data=None, text=""):
    mock = pytest.Mock()
    mock.status_code = status_code
    mock.json = lambda: json_data or {}
    mock.text = text
    return mock

def test_post_to_success(monkeypatch, capsys):
    fake_resp = make_response(201, {"id": 42})
    monkeypatch.setattr(run.requests, "post", lambda **kw: fake_resp)

    cfg = {"api_token":"T", "base_url":"u"}
    out = run.post_to("u/api", {"x":1}, cfg, success_msg="OK", failure_msg="NO")
    assert out == {"id":42}
    captured = capsys.readouterr()
    assert "OK" in captured.out

def test_post_to_http_error(monkeypatch, capsys):
    fake_resp = make_response(400, text="Bad")
    monkeypatch.setattr(run.requests, "post", lambda **kw: fake_resp)

    cfg = {"api_token":"T", "base_url":"u"}
    out = run.post_to("u/api", {"x":1}, cfg, success_msg="", failure_msg="FAIL")
    assert out is None
    captured = capsys.readouterr()
    assert "FAIL" in captured.out
    assert "400 Bad" in captured.out

def test_post_to_exception(monkeypatch, capsys):
    def boom(**kw):
        raise run.requests.exceptions.Timeout
    monkeypatch.setattr(run.requests, "post", boom)

    cfg = {"api_token":"T", "base_url":"u"}
    out = run.post_to("u/api", {}, cfg)
    assert out is None
    captured = capsys.readouterr()
    assert "Timeout" in captured.out

# 4.4 load_config: missing file
def test_load_config_missing(monkeypatch, tmp_path):
    # point configs/config.yml to a non-existent folder
    monkeypatch.chdir(tmp_path)
    with pytest.raises(FileNotFoundError):
        run.load_config()

# 4.5 execute_nmap: unsupported OS
def test_execute_nmap_unsupported_os(monkeypatch):
    monkeypatch.setattr(run.platform, "system", lambda: "AlienOS")
    with pytest.raises(SystemExit):
        run.execute_nmap("10.0.0.0/24")