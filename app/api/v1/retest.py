"""RedPulse - Remediation Verification (Retest) Endpoint.

POST /api/v1/findings/{finding_id}/verify-fix
"""

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession

from app.api.deps import get_current_user, get_db
from app.db.models import User
from app.services.retest_engine import retest_finding

router = APIRouter(tags=["retest"])


@router.post("/{finding_id}/verify-fix")
async def verify_fix(
    finding_id: str,
    db: AsyncSession = Depends(get_db),
    current_user: User = Depends(get_current_user),
):
    """Verify fix for a single finding via targeted micro-scan.

    If payload no longer triggers, marks finding as RESOLVED and returns verification badge.
    """
    try:
        result = await retest_finding(finding_id, db, current_user)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Retest failed: {e}")

    return {"success": True, "data": result}
