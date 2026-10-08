"""GitHub REST API client. Token comes only from the environment and is never logged or returned."""
from __future__ import annotations

import base64
import re

import httpx

OWNER_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]{1,100}$")
BRANCH_RE = re.compile(r"^security/fix-[A-Za-z0-9][A-Za-z0-9._-]{0,80}$")


class GitHubError(Exception):
    pass


class GitHubClient:
    def __init__(self, token: str | None, base_url: str, transport: httpx.BaseTransport | None = None):
        if not token:
            raise GitHubError("GITHUB_TOKEN is not configured on the server")
        self._http = httpx.Client(
            base_url=base_url, timeout=20, transport=transport,
            headers={"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json",
                     "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "SupplyGuard"},
        )

    def _call(self, method: str, path: str, ok=(200,), **kw):
        r = self._http.request(method, path, **kw)
        if r.status_code == 404 and 404 in ok:
            return None
        if r.status_code not in ok:
            try:
                msg = str(r.json().get("message", ""))[:200]
            except ValueError:
                msg = ""
            raise GitHubError(f"GitHub {method} returned HTTP {r.status_code}: {msg}")
        return r.json() if r.content else {}

    def repo_info(self, owner: str, repo: str) -> dict:
        return self._call("GET", f"/repos/{owner}/{repo}")

    def branch_sha(self, owner: str, repo: str, branch: str) -> str:
        data = self._call("GET", f"/repos/{owner}/{repo}/git/ref/heads/{branch}")
        return data["object"]["sha"]

    def create_branch(self, owner: str, repo: str, branch: str, sha: str) -> None:
        self._call("POST", f"/repos/{owner}/{repo}/git/refs", ok=(201,),
                   json={"ref": f"refs/heads/{branch}", "sha": sha})

    def get_file(self, owner: str, repo: str, path: str, branch: str) -> tuple[str, str] | None:
        data = self._call("GET", f"/repos/{owner}/{repo}/contents/{path}", ok=(200, 404), params={"ref": branch})
        if data is None:
            return None
        text = base64.b64decode(data["content"]).decode("utf-8")
        return text, data["sha"]

    def put_file(self, owner: str, repo: str, path: str, text: str, message: str, branch: str, sha: str) -> None:
        self._call("PUT", f"/repos/{owner}/{repo}/contents/{path}", ok=(200, 201), json={
            "message": message, "branch": branch, "sha": sha,
            "content": base64.b64encode(text.encode("utf-8")).decode("ascii"),
        })

    def open_pr(self, owner: str, repo: str, head: str, base: str, title: str, body: str) -> dict:
        data = self._call("POST", f"/repos/{owner}/{repo}/pulls", ok=(201,),
                          json={"title": title, "head": head, "base": base, "body": body, "draft": False})
        return {"url": data["html_url"], "number": data["number"]}
