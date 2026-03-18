from __future__ import annotations

import logging
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, field_validator

logger = logging.getLogger(__name__)

router = APIRouter()


class ComplianceOverlapRequest(BaseModel):
    frameworks: list[str]

    @field_validator("frameworks")
    @classmethod
    def frameworks_not_empty(cls, v: list[str]) -> list[str]:
        if not v:
            raise ValueError("frameworks list must not be empty")
        cleaned = [f.strip() for f in v if f.strip()]
        if not cleaned:
            raise ValueError("frameworks list contains only blank entries")
        return cleaned


class ComplianceOverlapResponse(BaseModel):
    overlap_matrix: dict[str, Any]
    shared_controls: int


def _get_compliance_v1_controls(framework: str) -> set[str]:
    """Query lib.compliance for controls belonging to a framework."""
    try:
        from lib.compliance import get_compliance_mapper

        mapper = get_compliance_mapper()
        all_controls = mapper.get_all_controls_for_framework(framework)
        return set(all_controls.keys())
    except ImportError as exc:
        raise RuntimeError("lib.compliance not available") from exc
    except Exception as exc:
        logger.error("compliance lookup failed for framework %r: %s", framework, exc)
        raise


def _build_overlap_matrix(
    framework_controls: dict[str, set[str]],
) -> dict[str, dict[str, int]]:
    frameworks = list(framework_controls.keys())
    matrix: dict[str, dict[str, int]] = {}
    for fw_a in frameworks:
        matrix[fw_a] = {}
        for fw_b in frameworks:
            overlap = len(framework_controls[fw_a] & framework_controls[fw_b])
            matrix[fw_a][fw_b] = overlap
    return matrix


def _count_shared_controls(framework_controls: dict[str, set[str]]) -> int:
    if len(framework_controls) < 2:
        return 0
    sets = list(framework_controls.values())
    common: set[str] = sets[0].copy()
    for s in sets[1:]:
        common &= s
    return len(common)


@router.post("/compliance/overlap", response_model=ComplianceOverlapResponse)
async def compliance_overlap(
    request: ComplianceOverlapRequest,
) -> ComplianceOverlapResponse:
    frameworks = request.frameworks

    framework_controls: dict[str, set[str]] = {}
    for fw in frameworks:
        try:
            framework_controls[fw] = _get_compliance_v1_controls(fw)
        except RuntimeError as exc:
            raise HTTPException(status_code=503, detail=str(exc)) from exc
        except Exception as exc:
            raise HTTPException(
                status_code=502,
                detail=f"Failed to retrieve controls for framework {fw!r}: {exc}",
            ) from exc

    overlap_matrix = _build_overlap_matrix(framework_controls)
    shared_controls = _count_shared_controls(framework_controls)

    return ComplianceOverlapResponse(
        overlap_matrix=overlap_matrix,
        shared_controls=shared_controls,
    )
