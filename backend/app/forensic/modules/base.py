"""The building blocks of an analysis: modules, the context they run in, and safe external tool execution.

A module is one self-contained analysis step (index the file system, extract artifacts, scan with YARA, ...).
It declares what it needs (`requires`), what it writes (`collections`: every document it inserts carries
`pipeline_module=<name>`), and how much of the job's progress it represents (`weight`). Because every output is
tagged with its module, one module can be cleared and re-run without touching the others' results.
"""
from __future__ import annotations
import os
import resource
import signal
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path

MAX_SUMMARY_WARNINGS = 200       # warnings kept on the job summary; all of them go to pipeline_warnings
DEFAULT_TOOL_MEMORY = 4 << 30    # address-space limit for external tools (bytes)
CANCEL_POLL_SECONDS = 2.0


class Cancelled(Exception):
    """The job was cancelled; raised at the next checkpoint (or while an external tool runs)."""


class Module:
    name = ''
    label = ''
    description = ''
    version = '1'
    requires: tuple[str, ...] = ()
    weight = 10
    collections: tuple[str, ...] = ()   # collections whose documents this module owns
    # Earlier modules this one also reads when they ran (without needing them): re-running one refreshes this one.
    follows: tuple[str, ...] = ()
    fields: dict[str, tuple[str, ...]] = {}  # fields this module sets on other modules' documents
    # The kinds of evidence the module applies to: a disk image, a logical package (collected files), a network capture.
    kinds: tuple[str, ...] = ('disk', 'logical')

    def clear(self, db, evidence_id: str):
        """Removes this module's previous output for one evidence item: its documents, and its fields on others'."""
        q = {'evidence_id': evidence_id, 'pipeline_module': self.name}
        for col in set(self.collections) | {'pipeline_warnings'}:
            db[col].delete_many(q)
        for col, names in self.fields.items():
            db[col].update_many({'evidence_id': evidence_id}, {'$unset': {n: '' for n in names}})
        db['analysis_facts'].update_one({'evidence_id': evidence_id}, {'$unset': {self.name: ''}})

    def run(self, ctx: 'ModuleContext') -> None:  # pragma: no cover - implemented by subclasses
        raise NotImplementedError


class ModuleContext:
    """Everything a module may use: the database, the evidence, the image to read, and job controls."""

    def __init__(self, *, db, evidence: dict, job_id: str, run_id: str, module: Module, image: Path, work: Path,
                 progress_cb=None, cancel_check=None, heartbeat=None, band=(0.0, 100.0), deadline: float | None = None):
        self.db = db
        self.evidence = evidence
        self.case_id = evidence['case_id']
        self.eid = evidence['evidence_id']
        self.job_id = job_id
        self.run_id = run_id
        self.module = module
        self.image = image
        self.work = work
        self.counts: dict[str, int] = {}
        self.warnings: list[str] = []
        self.warnings_total = 0
        self._progress_cb = progress_cb or (lambda p, s: None)
        self._cancel_check = cancel_check or (lambda: False)
        self._heartbeat = heartbeat or (lambda: None)
        self._band = band
        self._last_pct = band[0]
        self._last_poll = 0.0
        self._deadline = deadline
        self._source = None

    # -- evidence content -----------------------------------------------------------
    @property
    def kind(self) -> str:
        from ..source import evidence_kind
        return evidence_kind(self.evidence)

    @property
    def logical(self) -> bool:
        """A package of collected files (no partitions, no unallocated space, no deleted entries)."""
        from ..source import is_logical
        return is_logical(self.evidence)

    def source(self):
        """Where files are read from: the disk image through pytsk3, or the unpacked package's folders."""
        if self._source is None:
            from ..source import evidence_source
            self._source = evidence_source(self.evidence, self.image)
        return self._source

    # -- output ----------------------------------------------------------------
    def tag(self, doc: dict) -> dict:
        doc.update(pipeline=True, pipeline_module=self.module.name, module_run_id=self.run_id,
                   analysis_job_id=self.job_id)
        return doc

    def insert(self, collection: str, docs: list[dict]):
        if docs:
            self.db[collection].insert_many([self.tag(d) for d in docs], ordered=False)

    def count(self, key: str, n: int = 1):
        self.counts[key] = self.counts.get(key, 0) + n

    def warn(self, message: str):
        """Records a warning: all of them in pipeline_warnings, the first few on the job summary."""
        self.warnings_total += 1
        if len(self.warnings) < MAX_SUMMARY_WARNINGS:
            self.warnings.append(message)
        self.db['pipeline_warnings'].insert_one(self.tag({
            'evidence_id': self.eid, 'case_id': self.case_id, 'message': message[:2000],
            'created_at': datetime.now(timezone.utc)}))

    # -- facts shared between modules (kept per evidence, so a module can re-run alone) ----------------------
    def set_fact(self, key: str, value):
        self.db['analysis_facts'].update_one({'evidence_id': self.eid}, {'$set': {f'{self.module.name}.{key}': value}},
                                             upsert=True)

    def fact(self, module: str, key: str, default=None):
        doc = self.db['analysis_facts'].find_one({'evidence_id': self.eid}, {module: 1}) or {}
        return (doc.get(module) or {}).get(key, default)

    # -- job control -------------------------------------------------------------
    def checkpoint(self):
        """Raises Cancelled if the job was cancelled or ran out of time; refreshes the job heartbeat."""
        now = time.monotonic()
        if now - self._last_poll < CANCEL_POLL_SECONDS:
            return
        self._last_poll = now
        if self._cancel_check():
            raise Cancelled()
        if self._deadline is not None and time.time() > self._deadline:
            raise TimeoutError(f'{self.module.name} exceeded its time budget')
        self._heartbeat()

    def progress(self, fraction: float, detail: str = ''):
        """Reports progress within this module (0..1); the job's overall percentage never moves backwards."""
        lo, hi = self._band
        pct = int(lo + (hi - lo) * max(0.0, min(1.0, fraction)))
        pct = max(pct, int(self._last_pct))
        self._last_pct = pct
        self._progress_cb(pct, self.module.name + (f'@{detail}' if detail else ''))
        self.checkpoint()

    def _should_stop(self):
        self._heartbeat()  # a long tool run must not look like a dead worker
        return self._cancel_check()

    def run_tool(self, argv: list[str], *, timeout: float, stdout_path: Path | None = None,
                 max_output: int = 500_000, memory_bytes: int | None = DEFAULT_TOOL_MEMORY, file_bytes: int | None = None,
                 env: dict | None = None) -> dict:
        return run_tool(argv, timeout=timeout, stdout_path=stdout_path, max_output=max_output,
                        memory_bytes=memory_bytes, file_bytes=file_bytes, should_stop=self._should_stop, env=env)

    def stream_tool(self, argv: list[str], on_data, *, timeout: float, memory_bytes: int | None = DEFAULT_TOOL_MEMORY) -> dict:
        return stream_tool(argv, on_data, timeout=timeout, memory_bytes=memory_bytes, should_stop=self._should_stop)


def _limits(memory_bytes, file_bytes=None):
    def apply():
        os.setsid()  # own process group, so the whole tool tree can be killed
        if memory_bytes:
            try:
                resource.setrlimit(resource.RLIMIT_AS, (memory_bytes, memory_bytes))
            except (ValueError, OSError):
                pass
        if file_bytes:
            # No file the tool writes may grow past this (an archive bomb is stopped, not unpacked to fill the disk).
            resource.setrlimit(resource.RLIMIT_FSIZE, (file_bytes, file_bytes))
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    return apply


def _kill_group(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        pass
    try:
        proc.wait(timeout=5)
    except subprocess.TimeoutExpired:
        pass


def run_tool(argv: list[str], *, timeout: float, stdout_path: Path | None = None, max_output: int = 500_000,
             memory_bytes: int | None = DEFAULT_TOOL_MEMORY, file_bytes: int | None = None, should_stop=None, env: dict | None = None) -> dict:
    """Runs an external tool without a shell, in its own process group, under a memory limit and a timeout.

    stdout goes to `stdout_path` when given (large outputs such as bodyfiles), otherwise it is captured up to
    `max_output` bytes. Cancellation (`should_stop()`) and the timeout kill the whole process group. `env` adds to
    (or overrides) the environment the tool sees.
    Returns {status: COMPLETED|FAILED|TIMEOUT|CANCELLED|TOOL_UNAVAILABLE, returncode, stdout, stderr}.
    """
    import tempfile
    should_stop = should_stop or (lambda: False)
    if stdout_path:
        stdout_path.parent.mkdir(parents=True, exist_ok=True)
        out = stdout_path.open('wb')
    else:
        out = tempfile.TemporaryFile()
    err = tempfile.TemporaryFile()
    try:
        try:
            proc = subprocess.Popen(argv, stdout=out, stderr=err, stdin=subprocess.DEVNULL, shell=False,
                                    preexec_fn=_limits(memory_bytes, file_bytes), env={**os.environ, **env} if env else None)
        except FileNotFoundError:
            return {'status': 'TOOL_UNAVAILABLE', 'tool': argv[0], 'returncode': None, 'stdout': '', 'stderr': ''}
        started = time.monotonic()
        last_poll = 0.0
        status = None
        while True:
            try:
                proc.wait(timeout=0.25)
                break
            except subprocess.TimeoutExpired:
                pass
            now = time.monotonic()
            if now - started > timeout:
                status = 'TIMEOUT'
            elif now - last_poll >= CANCEL_POLL_SECONDS:
                last_poll = now
                if should_stop():
                    status = 'CANCELLED'
            if status:
                _kill_group(proc)
                break
        if status is None:
            status = 'COMPLETED' if proc.returncode == 0 else 'FAILED'
        err.seek(0)
        stderr = err.read(20_000).decode(errors='replace')
        stdout = ''
        if not stdout_path:
            out.seek(0)
            stdout = out.read(max_output).decode(errors='replace')
        if status == 'CANCELLED':
            raise Cancelled()
        return {'status': status, 'tool': argv[0], 'returncode': proc.returncode, 'stdout': stdout, 'stderr': stderr}
    finally:
        out.close()
        err.close()


def stream_tool(argv: list[str], on_data, *, timeout: float, memory_bytes: int | None = DEFAULT_TOOL_MEMORY,
                should_stop=None, chunk: int = 4 << 20) -> dict:
    """Runs an external tool like run_tool, handing its output to `on_data(bytes)` as it arrives instead of
    storing it (for example the unallocated space of a disk from blkls, which is never written out)."""
    import selectors
    import tempfile
    should_stop = should_stop or (lambda: False)
    err = tempfile.TemporaryFile()
    try:
        try:
            proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=err, stdin=subprocess.DEVNULL, shell=False,
                                    preexec_fn=_limits(memory_bytes), bufsize=0)
        except FileNotFoundError:
            return {'status': 'TOOL_UNAVAILABLE', 'tool': argv[0], 'returncode': None, 'stderr': ''}
        sel = selectors.DefaultSelector()
        sel.register(proc.stdout, selectors.EVENT_READ)
        started = last_poll = time.monotonic()
        status = None
        try:
            while True:
                now = time.monotonic()
                if now - started > timeout:
                    status = 'TIMEOUT'
                elif now - last_poll >= CANCEL_POLL_SECONDS:
                    last_poll = now
                    if should_stop():
                        status = 'CANCELLED'
                if status:
                    _kill_group(proc)
                    break
                if not sel.select(timeout=0.25):
                    continue
                data = os.read(proc.stdout.fileno(), chunk)
                if not data:
                    proc.wait()
                    break
                on_data(data)
        except BaseException:
            _kill_group(proc)
            raise
        finally:
            sel.close()
            proc.stdout.close()
        if status is None:
            status = 'COMPLETED' if proc.returncode == 0 else 'FAILED'
        err.seek(0)
        stderr = err.read(20_000).decode(errors='replace')
        if status == 'CANCELLED':
            raise Cancelled()
        return {'status': status, 'tool': argv[0], 'returncode': proc.returncode, 'stderr': stderr}
    finally:
        err.close()
