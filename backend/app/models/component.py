"""Normalized internal representation of SBOM components and graph edges."""
from __future__ import annotations

from typing import Optional
from pydantic import BaseModel, Field


class Component(BaseModel):
    ref: str                       # stable internal id within one scan, e.g. "npm:lodash@4.17.15"
    name: str
    version: Optional[str] = None  # None when the manifest does not pin a version
    ecosystem: str                 # "npm" | "PyPI" (OSV naming)
    purl: Optional[str] = None
    direct: Optional[bool] = None  # None = relationship could not be determined
    depth: Optional[int] = None    # shortest distance from application root
    license: Optional[str] = None
    hashes: dict[str, str] = Field(default_factory=dict)
    scope: Optional[str] = None    # "runtime" | "dev" | None
    source_format: str = "unknown"


class DependencyEdge(BaseModel):
    parent: str  # component ref ("" = application root)
    child: str


class ParseWarning(BaseModel):
    code: str
    message: str
    ref: Optional[str] = None


class ParsedSBOM(BaseModel):
    source_format: str
    app_name: Optional[str] = None
    components: list[Component] = Field(default_factory=list)
    edges: list[DependencyEdge] = Field(default_factory=list)
    warnings: list[ParseWarning] = Field(default_factory=list)
