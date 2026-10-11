"""The analysis modules, the processing profiles built from them, and how a job's run plan is worked out.

Profiles:
  quick     the file system index and the well-known artifacts, for a fast first look
  standard  everything that is cheap enough to run on every disk (the default)
  full      everything, including the expensive content modules as they are added

Planning a job: the requested modules, plus any prerequisite that has not completed (or was produced by an
older module version), plus every module that depends on something being re-run and had completed before, so
results built on replaced data are refreshed. The plan is always in dependency order.
"""
from __future__ import annotations

from .artifacts import ArtifactsModule
from .base import Cancelled, Module, ModuleContext, run_tool
from .computer import ComputerModule
from .fs_index import FsIndexModule
from .tz_probe import TzProbeModule
from .yara_scan import YaraModule

MODULES: list[Module] = [TzProbeModule(), FsIndexModule(), ComputerModule(), ArtifactsModule(), YaraModule()]
REGISTRY: dict[str, Module] = {m.name: m for m in MODULES}
ORDER = [m.name for m in MODULES]

PROFILES = {
    'quick': ['tz_probe', 'fs_index', 'computer', 'artifacts'],
    'standard': ['tz_probe', 'fs_index', 'computer', 'artifacts', 'yara'],
    'full': ['tz_probe', 'fs_index', 'computer', 'artifacts', 'yara'],
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
        for r in m.requires:
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
            if m.name not in selected and current(m.name) and any(r in selected for r in m.requires):
                selected.add(m.name)
                changed = True
    return [n for n in ORDER if n in selected]


def describe() -> dict:
    """Modules and profiles, for the API and the Analyze dialog."""
    return {
        'modules': [{'name': m.name, 'label': m.label, 'description': m.description, 'requires': list(m.requires),
                     'version': m.version} for m in MODULES],
        'profiles': [{'name': p, 'label': PROFILE_LABELS[p], 'modules': PROFILES[p]} for p in PROFILES],
        'default_profile': DEFAULT_PROFILE,
    }


__all__ = ['Cancelled', 'Module', 'ModuleContext', 'run_tool', 'MODULES', 'REGISTRY', 'ORDER', 'PROFILES',
           'DEFAULT_PROFILE', 'resolve_request', 'plan', 'describe']
