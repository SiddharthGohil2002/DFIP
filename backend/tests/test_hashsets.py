"""Hash sets: importing plain lists, CSV and NSRL RDS v3 SQLite into per-set stores, and batched lookups."""
import hashlib
import sqlite3

import pytest

from app.forensic.hashsets import import_set, lookup


def _h(algo, text):
    return hashlib.new(algo, text.encode()).hexdigest()


MD5_A, SHA1_A, SHA256_A = _h('md5', 'a'), _h('sha1', 'a'), _h('sha256', 'a')
SHA256_B = _h('sha256', 'b')


def test_plain_text_list(tmp_path):
    src = tmp_path / 'list.txt'
    src.write_text('\n'.join([
        '# demo known-bad list',
        '',
        MD5_A,
        SHA1_A.upper(),                         # upper case is accepted
        f'{SHA256_A}  eicar.com',               # sha256sum output
        f'\\{SHA256_B} *odd\\nname',            # sha256sum escapes names with backslashes
        SHA256_A,                               # duplicates are stored once
        'not-a-hash',
        'abc123',                               # hex, but no digest length
        MD5_A + '0',                            # 33 hex digits
    ]) + '\n')
    store = tmp_path / 'set.sqlite'
    r = import_set(src, store)
    assert r == {'format': 'text', 'counts': {'md5': 1, 'sha1': 1, 'sha256': 2}, 'invalid': 3}
    assert lookup(store, 'sha256', [SHA256_A, SHA256_B, _h('sha256', 'c')]) == {SHA256_A, SHA256_B}
    assert lookup(store, 'md5', [MD5_A.upper()]) == {MD5_A}
    assert lookup(store, 'sha1', [SHA1_A]) == {SHA1_A}
    # Digests are only found under their own algorithm.
    assert lookup(store, 'sha1', [MD5_A]) == set()


def test_csv_with_header(tmp_path):
    src = tmp_path / 'set.csv'
    src.write_text('"FileName","SHA-256","MD5","Size"\n'
                   f'"eicar.com","{SHA256_A}","{MD5_A}",68\n'
                   f'"holiday.jpg","{SHA256_B}","",2191\n'
                   '"broken","zzzz","",1\n')
    store = tmp_path / 'set.sqlite'
    r = import_set(src, store)
    assert r['format'] == 'CSV' and r['counts'] == {'md5': 1, 'sha1': 0, 'sha256': 2} and r['invalid'] == 1
    assert lookup(store, 'sha256', [SHA256_B]) == {SHA256_B}


def test_csv_values_must_match_their_column(tmp_path):
    src = tmp_path / 'set.csv'
    src.write_text(f'name,sha1\nx,{MD5_A}\ny,{SHA1_A}\n')  # an MD5 in the sha1 column is invalid
    r = import_set(src, tmp_path / 'set.sqlite')
    assert r['counts']['sha1'] == 1 and r['counts']['md5'] == 0 and r['invalid'] == 1


def test_nsrl_rds_v3_sqlite(tmp_path):
    src = tmp_path / 'RDS_modern.db'
    con = sqlite3.connect(src)
    con.execute('CREATE TABLE FILE (sha256 TEXT, sha1 TEXT, md5 TEXT, crc32 TEXT, file_name TEXT, file_size INTEGER, package_id INTEGER)')
    con.executemany('INSERT INTO FILE VALUES (?,?,?,?,?,?,?)', [
        (SHA256_A.upper(), SHA1_A.upper(), MD5_A.upper(), '00000000', 'notepad.exe', 1, 1),
        (SHA256_B, None, '', '00000000', 'calc.exe', 2, 1),
    ])
    con.commit()
    con.close()
    store = tmp_path / 'set.sqlite'
    r = import_set(src, store)
    assert r == {'format': 'NSRL RDS v3 (SQLite)', 'counts': {'md5': 1, 'sha1': 1, 'sha256': 2}, 'invalid': 0}
    assert lookup(store, 'sha256', [SHA256_A, SHA256_B]) == {SHA256_A, SHA256_B}


def test_sqlite_without_a_file_table_is_rejected(tmp_path):
    src = tmp_path / 'other.db'
    con = sqlite3.connect(src)
    con.execute('CREATE TABLE something (x)')
    con.commit()
    con.close()
    with pytest.raises(ValueError, match='FILE table'):
        import_set(src, tmp_path / 'set.sqlite')


def test_store_layout_and_large_lookups(tmp_path):
    digests = [_h('sha256', str(i)) for i in range(2500)]
    src = tmp_path / 'big.txt'
    src.write_text('\n'.join(digests) + '\n')
    store = tmp_path / 'set.sqlite'
    assert import_set(src, store)['counts']['sha256'] == 2500
    con = sqlite3.connect(store)
    sql = dict(con.execute("SELECT name, sql FROM sqlite_master WHERE type='table'").fetchall())
    stored = con.execute('SELECT h FROM sha256 LIMIT 1').fetchone()[0]
    con.close()
    assert set(sql) == {'md5', 'sha1', 'sha256'} and all('WITHOUT ROWID' in s for s in sql.values())
    assert isinstance(stored, bytes) and len(stored) == 32  # raw digests, not hex text
    # Lookups are batched: more digests than one SQL statement takes, half of them in the set.
    probe = digests[::2] + [_h('sha256', f'x{i}') for i in range(1250)]
    assert lookup(store, 'sha256', probe) == set(digests[::2])


def test_reimport_replaces_the_store(tmp_path):
    store = tmp_path / 'set.sqlite'
    (tmp_path / 'one.txt').write_text(SHA256_A + '\n')
    (tmp_path / 'two.txt').write_text(SHA256_B + '\n')
    import_set(tmp_path / 'one.txt', store)
    import_set(tmp_path / 'two.txt', store)
    assert lookup(store, 'sha256', [SHA256_A, SHA256_B]) == {SHA256_B}


@pytest.mark.parametrize('header', ['', 'sha256,name\n'])
def test_progress_is_reported_while_importing(tmp_path, header):
    src = tmp_path / 'big.txt'
    with src.open('w') as f:
        f.write(header)
        for i in range(250_000):
            f.write(f'{i:064x},f{i}\n' if header else f'{i:064x}\n')
    seen = []
    r = import_set(src, tmp_path / 'set.sqlite', seen.append)
    assert r['counts']['sha256'] == 250_000 and r['invalid'] == 0
    assert len(seen) >= 2 and seen == sorted(seen) and 0 < seen[-1] < 1
