import uuid
from typing import TYPE_CHECKING, Any, Optional
from sqlalchemy import Float, ForeignKey, Index, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.types import JSON
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base

if TYPE_CHECKING:
    from app.models.mitigation import Mitigation
    from app.models.scan import Scan


class Finding(Base):
    __tablename__ = "findings"

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        default=uuid.uuid4,
        nullable=False,
    )
    scan_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("scans.scan_id", ondelete="CASCADE"),
        nullable=False,
    )
    mitigation_id: Mapped[Optional[uuid.UUID]] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("mitigations.id", ondelete="SET NULL"),
        nullable=True,
    )
    file_path: Mapped[str] = mapped_column(String(500), nullable=False)
    start_line: Mapped[int] = mapped_column(Integer, nullable=False)
    end_line: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    cwe_id: Mapped[Optional[str]] = mapped_column(String(50), nullable=True)
    owasp: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    source: Mapped[str] = mapped_column(String(20), nullable=False)
    rule_id: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    snippet: Mapped[str] = mapped_column(Text, nullable=False)
    ml_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    severity: Mapped[str] = mapped_column(String(20), nullable=False)
    risk_score: Mapped[float] = mapped_column(Float, nullable=False)
    mitigation: Mapped[str] = mapped_column(Text, nullable=False)
    status: Mapped[str] = mapped_column(String(20), nullable=False, default="open")

    # Phase 16 Additive Fields: CVSS v3.1, Security Frameworks, Explainable Correlation
    cvss_score: Mapped[Optional[float]] = mapped_column(Float, nullable=True)
    cvss_vector: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    cvss_severity: Mapped[Optional[str]] = mapped_column(String(20), nullable=True)
    cvss_provenance: Mapped[str] = mapped_column(String(30), nullable=False, default="unassessed")
    security_frameworks: Mapped[Optional[Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )
    correlation_data: Mapped[Optional[Any]] = mapped_column(
        JSON().with_variant(JSONB, "postgresql"),
        nullable=True,
    )

    # Table indexes
    __table_args__ = (
        Index("ix_findings_scan_id_severity", "scan_id", "severity"),
        Index("ix_findings_status", "status"),
    )

    # Relationships
    scan: Mapped["Scan"] = relationship("Scan", back_populates="findings")
    mitigation_detail: Mapped[Optional["Mitigation"]] = relationship(
        "Mitigation",
        back_populates="findings",
    )
