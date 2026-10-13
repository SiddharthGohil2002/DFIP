"""Controlled adapters for external forensic tooling.

All commands are allow-listed, run without shell=True, have bounded time/output,
and are read-only against original evidence. Write operations are restricted to
DFIP's analysis/recovery directories.
"""
from pathlib import Path
import shutil, subprocess

TOOLS = {
    'sleuthkit_fls': 'fls',
    'sleuthkit_istat': 'istat',
    'sleuthkit_fsstat': 'fsstat',
    'sleuthkit_mmls': 'mmls',
    'sleuthkit_icat': 'icat',
    'sleuthkit_blkls': 'blkls',
    'exiftool': 'exiftool',
    'tshark': 'tshark',
    'yara': 'yara',
    'volatility': 'vol',
    'strings': 'strings',
    'file': 'file',
}

FORENSIC_IMAGE_EXTS = {'E01','EX01','RAW','DD','AFF','AFF4'}


def inventory():
    return {name: {'binary': binary, 'available': bool(shutil.which(binary))}
            for name, binary in TOOLS.items()}


def run(name: str, args: list[str], timeout=60, max_output=500_000):
    if name not in TOOLS:
        raise ValueError('Tool is not allow-listed')
    binary = shutil.which(TOOLS[name])
    if not binary:
        return {'available': False, 'tool': name, 'output': ''}
    if any(not isinstance(a, str) or '\x00' in a for a in args):
        raise ValueError('Invalid tool argument')
    try:
        proc = subprocess.run([binary, *args], capture_output=True, text=True,
                              timeout=timeout, check=False, shell=False)
    except subprocess.TimeoutExpired as exc:
        return {'available': True, 'tool': name, 'returncode': -9,
                'stdout': (exc.stdout or '')[:max_output] if isinstance(exc.stdout, str) else '',
                'stderr': 'TIMEOUT'}
    out = (proc.stdout or '')[:max_output]
    err = (proc.stderr or '')[:max_output]
    return {'available': True, 'tool': name, 'returncode': proc.returncode,
            'stdout': out, 'stderr': err}


def parse_mmls(path: Path):
    r = run('sleuthkit_mmls', [str(path)], timeout=90, max_output=100_000)
    partitions = []
    if r.get('available') and r.get('returncode') == 0:
        for line in r.get('stdout','').splitlines():
            s=line.strip()
            if not s or s.lower().startswith(('offset','units','slot','dos partition','gpt','mac partition','bsd')):
                continue
            cols=s.split()
            if len(cols) >= 6:
                # mmls rows: "002:  000:000   0000002048   0000131071   0000129024   Win95 FAT32 (0x0c)"
                # -> index, slot (Meta / ------- / table:entry), start, end, length, description
                try:
                    start=int(cols[2])
                    end=int(cols[3])
                    length=int(cols[4])
                except (ValueError, IndexError):
                    continue
                slot=cols[1]
                partitions.append({'index':cols[0].rstrip(':'), 'slot':slot, 'start':start, 'end':end,
                                   'length':length, 'description':' '.join(cols[5:]),
                                   'is_meta':slot.lower()=='meta', 'is_unallocated':set(slot)=={'-'}})
    return {'status':'COMPLETED' if r.get('returncode') == 0 else ('TOOL_UNAVAILABLE' if not r.get('available') else 'FAILED'),
            'tool':'mmls', 'partitions':partitions, 'stdout':r.get('stdout',''), 'stderr':r.get('stderr','')}


def parse_filesystem(path: Path, format_name: str, offset: int = 0):
    if format_name.upper() not in FORENSIC_IMAGE_EXTS:
        return {'status':'UNSUPPORTED','artifacts':[]}
    args=['-r','-m','/']
    if offset:
        args += ['-o', str(offset)]
    args.append(str(path))
    result=run('sleuthkit_fls', args, timeout=180, max_output=1_000_000)
    from .filesystem import parse_bodyfile_line
    artifacts=[]
    if result.get('available') and result.get('returncode') == 0:
        for line in result.get('stdout','').splitlines()[:20_000]:
            entry=parse_bodyfile_line(line)
            if entry:
                artifacts.append(dict(entry, raw=line, source='SLEUTH_KIT', offset=offset))
    return {'status':'COMPLETED' if result.get('returncode')==0 else ('TOOL_UNAVAILABLE' if not result.get('available') else 'FAILED'),
            'tool':'fls','offset':offset,'artifacts':artifacts,'stderr':result.get('stderr','')}


def filesystem_stats(path: Path, offset: int = 0):
    args=[]
    if offset: args += ['-o', str(offset)]
    args.append(str(path))
    r=run('sleuthkit_fsstat',args,timeout=120,max_output=200_000)
    return {'status':'COMPLETED' if r.get('returncode')==0 else ('TOOL_UNAVAILABLE' if not r.get('available') else 'FAILED'),
            'tool':'fsstat','offset':offset,'stdout':r.get('stdout',''),'stderr':r.get('stderr','')}


def inode_stat(path: Path, inode: int, offset: int = 0):
    args=[]
    if offset: args += ['-o', str(offset)]
    args += [str(path), str(inode)]
    r=run('sleuthkit_istat',args,timeout=60,max_output=100_000)
    return {'status':'COMPLETED' if r.get('returncode')==0 else ('TOOL_UNAVAILABLE' if not r.get('available') else 'FAILED'),
            'tool':'istat','inode':inode,'offset':offset,'stdout':r.get('stdout',''),'stderr':r.get('stderr','')}


def recover_file(image: Path, inode: int | str, destination: Path, offset: int = 0, volume_args: list[str] | None = None):
    """icat a file to destination; volume_args select the volume when the offset alone does not (an APFS volume)."""
    destination.parent.mkdir(parents=True, exist_ok=True)
    args=list(volume_args or [])
    if offset and not volume_args: args += ['-o', str(offset)]
    args += [str(image), str(inode)]
    binary=shutil.which(TOOLS['sleuthkit_icat'])
    if not binary:
        return {'status':'TOOL_UNAVAILABLE','tool':'icat'}
    try:
        with destination.open('wb') as out:
            p=subprocess.run([binary,*args],stdout=out,stderr=subprocess.PIPE,timeout=300,check=False,shell=False)
        return {'status':'COMPLETED' if p.returncode==0 else 'FAILED','tool':'icat','inode':inode,
                'offset':offset,'returncode':p.returncode,'stderr':(p.stderr or b'').decode(errors='replace')[:100_000]}
    except subprocess.TimeoutExpired:
        destination.unlink(missing_ok=True)
        return {'status':'TIMEOUT','tool':'icat','inode':inode,'offset':offset}


def inspect_file(path: Path):
    r=run('exiftool',['-json','-G1','-a','-s',str(path)],timeout=90,max_output=500_000)
    return r


def scan_yara(rule_file: Path, target: Path):
    return run('yara',['-r','-w',str(rule_file),str(target)],timeout=180,max_output=500_000)


def extract_strings(path: Path):
    return run('strings',['-a','-n','6',str(path)],timeout=180,max_output=500_000)


def inspect_pcap(path: Path):
    return run('tshark',['-r',str(path),'-T','json'],timeout=300,max_output=1_000_000)


def inspect_memory(path: Path):
    # Volatility3 command is optional. No arbitrary plugins are accepted here.
    return run('volatility',['-f',str(path),'windows.info'],timeout=300,max_output=500_000)
