"""Remediation planning and manifest patching. Plans only; nothing is installed or executed here."""
from __future__ import annotations

import difflib
import json
import re

from packaging.version import InvalidVersion, Version

from app.engines.versions import minimal_fix_above
from app.models.component import Component


def _vkey(v: str):
    try:
        return Version(v)
    except InvalidVersion:
        return Version("0")


def plan_for_component(comp: Component, vulns: list[tuple[str, list[str]]], direct: bool | None) -> dict | None:
    """vulns: list of (finding_id, fixed_versions). Target is the lowest version that contains every
    published fix for the package, so one upgrade clears every fixable finding on it."""
    if not comp.version:
        return None
    fixes, unfixable = [], []
    for fid, fixed in vulns:
        fx = minimal_fix_above(comp.version, fixed)
        if fx:
            fixes.append(fx)
        else:
            unfixable.append(fid)
    if not fixes:
        return None
    target = max(fixes, key=_vkey)
    is_direct = direct is True
    if comp.ecosystem == "npm":
        if is_direct:
            commands = [f"npm install {comp.name}@{target}"]
            kind = "direct"
            change = f'package.json: "{comp.name}" -> "{target}"'
        else:
            commands = [f'package.json "overrides": {{"{comp.name}": "{target}"}}', "npm install --package-lock-only"]
            kind = "transitive"
            change = f'package.json: add override "{comp.name}": "{target}"'
        files = ["package.json", "package-lock.json"]
    elif comp.ecosystem == "PyPI":
        commands = [f"{comp.name}=={target} in requirements.txt"]
        kind = "direct" if is_direct else "transitive"
        change = f"requirements.txt: pin {comp.name}=={target}"
        files = ["requirements.txt"]
    else:
        return None
    return {
        "component_ref": comp.ref, "name": comp.name, "ecosystem": comp.ecosystem,
        "current_version": comp.version, "target_version": target, "kind": kind,
        "commands": commands, "files_changed": files, "change": change,
        "clears_findings": [f for f, _ in vulns if f not in unfixable],
        "unfixable_findings": unfixable,
        "rationale": (f"{comp.name} {comp.version} is affected by {len(vulns)} known "
                      f"vulnerabilit{'y' if len(vulns) == 1 else 'ies'}. {target} is the lowest version that "
                      f"contains every published fix, so one upgrade clears all fixable findings on this package."),
    }


def apply_plan(files: dict[str, str], plan: dict) -> dict[str, str]:
    """Return patched copies of the manifests. Only the planned change is made."""
    out = dict(files)
    name, target = plan["name"], plan["target_version"]
    if plan["ecosystem"] == "npm" and "package.json" in files:
        data = json.loads(files["package.json"])
        if plan["kind"] == "direct":
            for section in ("dependencies", "devDependencies", "optionalDependencies"):
                if name in data.get(section, {}):
                    data[section][name] = target
        else:
            data.setdefault("overrides", {})[name] = target
        out["package.json"] = json.dumps(data, indent=2) + "\n"
    elif plan["ecosystem"] == "PyPI":
        for path in [p for p in files if p.endswith("requirements.txt")]:
            lines = files[path].splitlines()
            norm = re.sub(r"[-_.]+", "-", name).lower()
            found = False
            new_lines = []
            for line in lines:
                m = re.match(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)", line)
                if m and re.sub(r"[-_.]+", "-", m.group(1)).lower() == norm:
                    new_lines.append(f"{name}=={target}")
                    found = True
                else:
                    new_lines.append(line)
            if found:
                out[path] = "\n".join(new_lines) + "\n"
    return out


def diff_text(old: str, new: str, path: str) -> str:
    return "".join(difflib.unified_diff(old.splitlines(keepends=True), new.splitlines(keepends=True),
                                        fromfile=f"a/{path}", tofile=f"b/{path}"))
