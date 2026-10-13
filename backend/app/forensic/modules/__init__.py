"""The analysis modules, the processing profiles built from them, and how a job's run plan is worked out.

Profiles:
  quick     the file system index, the well-known artifacts, phones and network captures, for a fast first look
  standard  everything that is cheap enough to run on every disk (the default): also event logs, Jump Lists, the
            Windows Timeline, thumbnails, SRUM and the search index, NTFS timestomping, alternate data streams and the USN
            journal, Volume Shadow Copies (what changed since each), browser searches, cookies, bookmarks, logins and deleted history, email, chat and cloud storage, file
            hashes and types, picture thumbnails, camera and GPS metadata and video keyframes, programs (PE analysis,
            signatures, capa), ClamAV, VirusTotal lookups when a case turns them on, hash sets and YARA
  full      everything: also archive members and embedded files, text in pictures and scans (OCR), the text of every file
            and of unallocated space (content search), and the data found in it

Planning a job: the requested modules, plus any prerequisite that has not completed (or was produced by an
older module version), plus every module that depends on something being re-run (or follows it: reads its output
when it ran) and had completed before, so results built on replaced data are refreshed. The plan is always in
dependency order.
"""
from __future__ import annotations

from .artifacts import ArtifactsModule
from .base import Cancelled, Module, ModuleContext, run_tool
from .browser_depth import BrowserDepthModule
from .chat_cloud import ChatCloudModule
from .clamav import ClamavModule
from .computer import ComputerModule
from .email_stores import EmailModule
from .eventlogs import EventLogsModule
from .executables import ExecutablesModule
from .content import ContentModule
from .fileproc import FileProcModule
from .found import FoundDataModule
from .fs_index import FsIndexModule
from .hash_match import HashMatchModule
from .media import MediaModule
from .members import MembersModule
from .network import NetworkModule
from .ntfs import NtfsModule
from .ocr import OcrModule
from .phone import PhoneModule
from .registry import RegistryModule
from .reputation import ReputationModule
from .shadow_copies import ShadowCopiesModule
from .tz_probe import TzProbeModule
from .unix import UnixModule
from .unallocated import UnallocatedModule
from .user_activity import UserActivityModule
from .yara_scan import YaraModule

MODULES: list[Module] = [TzProbeModule(), FsIndexModule(), ComputerModule(), ArtifactsModule(), RegistryModule(), UnixModule(), PhoneModule(),
                         EventLogsModule(),
                         UserActivityModule(), NtfsModule(), ShadowCopiesModule(), BrowserDepthModule(), FileProcModule(), MembersModule(), EmailModule(),
                         ChatCloudModule(), NetworkModule(), MediaModule(), OcrModule(), ExecutablesModule(), ReputationModule(), ClamavModule(),
                         HashMatchModule(), YaraModule(), ContentModule(), UnallocatedModule(), FoundDataModule()]
REGISTRY: dict[str, Module] = {m.name: m for m in MODULES}
ORDER = [m.name for m in MODULES]

PROFILES = {
    'quick': ['tz_probe', 'fs_index', 'computer', 'artifacts', 'registry', 'unix', 'phone', 'network'],
    'standard': ['tz_probe', 'fs_index', 'computer', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies',
                 'browser_depth', 'fileproc', 'email', 'chat_cloud', 'network', 'media', 'executables', 'reputation', 'clamav', 'hash_match', 'yara'],
    'full': ['tz_probe', 'fs_index', 'computer', 'artifacts', 'registry', 'unix', 'phone', 'eventlogs', 'user_activity', 'ntfs', 'shadow_copies', 'browser_depth',
             'fileproc', 'containers', 'email', 'chat_cloud', 'network', 'media', 'ocr', 'executables', 'reputation', 'clamav', 'hash_match', 'yara', 'content',
             'unallocated', 'found_data'],
}
DEFAULT_PROFILE = 'standard'
PROFILE_LABELS = {
    'quick': 'Quick triage',
    'standard': 'Standard',
    'full': 'Full',
}


def _check_graph():
    """Every requirement exists and comes earlier in ORDER (so ORDER is a valid dependency order)."""
    for i, m in enumerate(MODULES):
        for r in m.requires + m.follows:
            if r not in REGISTRY or ORDER.index(r) >= i:
                raise RuntimeError(f'Module {m.name} requires {r}, which is unknown or not earlier in the order')


_check_graph()


def resolve_request(profile: str | None = None, modules: list[str] | None = None) -> list[str]:
    """The modules a caller asked for: an explicit list, else a profile, else the default profile."""
    if modules:
        unknown = [m for m in modules if m not in REGISTRY]
        if unknown:
            raise ValueError(f'Unknown analysis module(s): {", ".join(unknown)}')
        return list(dict.fromkeys(modules))
    profile = profile or DEFAULT_PROFILE
    if profile not in PROFILES:
        raise ValueError(f'Unknown analysis profile: {profile}')
    return list(PROFILES[profile])


def plan(requested: list[str], status: dict[str, dict] | None = None) -> list[str]:
    """The run plan for `requested`, given each module's current status on the evidence."""
    status = status or {}

    def current(name):
        s = status.get(name) or {}
        return s.get('status') == 'COMPLETED' and str(s.get('version')) == REGISTRY[name].version

    selected = set(requested)
    changed = True
    while changed:
        changed = False
        for name in list(selected):
            for req in REGISTRY[name].requires:
                if req not in selected and not current(req):
                    selected.add(req)
                    changed = True
        for m in MODULES:
            if m.name not in selected and current(m.name) and any(r in selected for r in m.requires + m.follows):
                selected.add(m.name)
                changed = True
    return [n for n in ORDER if n in selected]


def describe() -> dict:
    """Modules and profiles, for the API and the Analyze dialog."""
    return {
        'modules': [{'name': m.name, 'label': m.label, 'description': m.description, 'requires': list(m.requires),
                     'version': m.version, 'kinds': list(m.kinds)} for m in MODULES],
        'profiles': [{'name': p, 'label': PROFILE_LABELS[p], 'modules': PROFILES[p]} for p in PROFILES],
        'default_profile': DEFAULT_PROFILE,
    }


__all__ = ['Cancelled', 'Module', 'ModuleContext', 'run_tool', 'MODULES', 'REGISTRY', 'ORDER', 'PROFILES',
           'DEFAULT_PROFILE', 'resolve_request', 'plan', 'describe']
