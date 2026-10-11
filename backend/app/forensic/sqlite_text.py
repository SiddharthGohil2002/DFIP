"""Text values of an SQLite database from an evidence file, one value per line.

Run as a separate process (`python -m app.forensic.sqlite_text <database> <output>`, through run_tool with a
timeout and a memory limit), because the database is untrusted: it is opened read-only and immutable, schema
code is not trusted, and only plain tables are read. Raw strings of a database run one field into the next
(SQLite stores a record's fields back to back), so a URL would be followed by the page title; reading the
values keeps them apart. Records deleted from the database are not read here.
"""
import sqlite3
import sys

MAX_CHARS = 8_000_000
MAX_ROWS = 2_000_000


def dump(db_path: str, out_path: str) -> int:
    con = sqlite3.connect(f'file:{db_path}?mode=ro&immutable=1', uri=True)
    con.execute('PRAGMA trusted_schema = OFF')
    con.execute('PRAGMA cell_size_check = ON')
    tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table' AND sql NOT LIKE 'CREATE VIRTUAL%'")]
    written = rows = 0
    with open(out_path, 'w', encoding='utf-8', newline='\n') as out:
        for t in tables:
            try:
                cur = con.execute(f'SELECT * FROM "{t.replace(chr(34), chr(34) * 2)}"')
            except sqlite3.Error:
                continue
            for row in cur:
                rows += 1
                for v in row:
                    if isinstance(v, bytes):
                        try:
                            v = v.decode('utf-8')
                        except UnicodeDecodeError:
                            continue
                    if isinstance(v, str) and v.strip():
                        line = v.replace('\x00', ' ').replace('\r', ' ').replace('\n', ' ')
                        out.write(line + '\n')
                        written += len(line) + 1
                        if written >= MAX_CHARS:
                            return written
                if rows >= MAX_ROWS:
                    return written
    con.close()
    return written


if __name__ == '__main__':
    dump(sys.argv[1], sys.argv[2])
