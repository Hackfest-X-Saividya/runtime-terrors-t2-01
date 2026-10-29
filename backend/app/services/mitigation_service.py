import uuid
from typing import Optional
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.models.mitigation import Mitigation
from app.services.analyzers.base import FindingDraft


def generate_canonical_key(draft: FindingDraft) -> str:
    """
    Generates a deterministic canonical key for deduplicating remediations:
    - Rule-specific: 'rule:<rule_id>'
    - CWE-generic: 'cwe:<cwe_id>:generic'
    - Custom unmapped: 'custom:<uuid>'
    """
    if draft.rule_id:
        return f"rule:{draft.rule_id.strip()}"
    if draft.cwe_id:
        return f"cwe:{draft.cwe_id.strip().upper()}:generic"
    return f"custom:{uuid.uuid4()}"


async def get_or_create_mitigation(session: AsyncSession, draft: FindingDraft) -> uuid.UUID:
    """
    Ensures a canonical mitigation record exists in the catalog.
    Returns the mitigation UUID.
    """
    canonical_key = generate_canonical_key(draft)

    # 1. Look up existing catalog entry
    stmt = select(Mitigation.id).where(Mitigation.canonical_key == canonical_key)
    result = await session.execute(stmt)
    existing_id = result.scalar_one_or_none()

    if existing_id is not None:
        return existing_id

    # 2. Insert new mitigation catalog entry
    new_mitigation = Mitigation(
        id=uuid.uuid4(),
        canonical_key=canonical_key,
        cwe_id=draft.cwe_id,
        rule_id=draft.rule_id,
        title=f"Remediation for {draft.title}",
        remediation_guidance=draft.mitigation,
        code_diff=None,
        references_json=[f"https://cwe.mitre.org/data/definitions/{draft.cwe_id.split('-')[-1]}.html"]
        if draft.cwe_id
        else None,
    )
    session.add(new_mitigation)
    await session.flush()
    return new_mitigation.id
