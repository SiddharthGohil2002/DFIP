from pathlib import Path
from app.forensic.hashing import sha256_file

def test_sha256(tmp_path: Path):
    p=tmp_path/'sample.bin'
    p.write_bytes(b'DFIP forensic evidence test')
    assert sha256_file(p)=='4ec2416d61518459f843b1f4277c302d06a6017620b9602f4dc750e62838972c'
