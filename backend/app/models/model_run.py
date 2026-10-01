"""Tracks each trained ML model artifact and evaluation run
(docs/ml/ml-pipeline.md §6). Every Alert.model_version foreign-keys here by
value so a score can always be traced back to exactly which trained model
produced it, with that model's own evaluation metrics alongside it.
"""

from datetime import datetime

from sqlalchemy import DateTime, Float, Integer, String, func
from sqlalchemy.dialects.postgresql import JSONB
from sqlalchemy.orm import Mapped, mapped_column

from app.core.db import Base
from app.models.base import UUIDPrimaryKeyMixin


class ModelRun(UUIDPrimaryKeyMixin, Base):
    __tablename__ = "model_runs"

    model_version: Mapped[str] = mapped_column(String(50), unique=True, nullable=False)
    model_type: Mapped[str] = mapped_column(String(50), nullable=False)  # "isolation_forest", ...
    trained_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), server_default=func.now(), nullable=False
    )
    training_sample_count: Mapped[int] = mapped_column(Integer, nullable=False)
    feature_schema: Mapped[dict] = mapped_column(JSONB, nullable=False)
    hyperparameters: Mapped[dict] = mapped_column(JSONB, nullable=False)

    # Evaluation metrics (docs/evaluation.md §2) — computed and stored, not
    # asserted in documentation.
    precision: Mapped[float | None] = mapped_column(Float, nullable=True)
    recall: Mapped[float | None] = mapped_column(Float, nullable=True)
    pr_auc: Mapped[float | None] = mapped_column(Float, nullable=True)

    artifact_path: Mapped[str] = mapped_column(String(500), nullable=False)
    is_active: Mapped[bool] = mapped_column(default=False, nullable=False)
