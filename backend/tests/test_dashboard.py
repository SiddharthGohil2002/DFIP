"""Activity dashboard helpers: website host names and the time zone parameter."""
import pytest

from app.analysis.dashboard import host_of, valid_tz


@pytest.mark.parametrize('url,host', [
    ('https://www.google.com/search?q=x', 'google.com'),
    ('https://filetransfer.example.net/upload', 'filetransfer.example.net'),
    ('http://intranet.corp.example:8080/hr', 'intranet.corp.example'),
    ('file:///C:/Users/alice/Downloads/archiver.zip', '(local or invalid URL)'),
    ('', '(local or invalid URL)'),
    (None, '(local or invalid URL)'),
    ('http://[::1', '(local or invalid URL)'),
])
def test_host_of(url, host):
    assert host_of(url) == host


@pytest.mark.parametrize('tz', ['UTC', 'Asia/Kolkata', 'America/New_York', 'America/Argentina/Buenos_Aires', 'Etc/GMT+5', '+05:30', '-04:00'])
def test_valid_time_zones(tz):
    assert valid_tz(tz)


@pytest.mark.parametrize('tz', ['', 'Asia/Kolkata; drop', '05:30', '+5:30', '$where', 'a' * 65, '../etc'])
def test_invalid_time_zones(tz):
    assert not valid_tz(tz)
