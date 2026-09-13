"""
SentinelAI - Pydantic request schemas.
"""

from typing import Dict, Optional

from pydantic import BaseModel, Field, model_validator


class ClassifyRequest(BaseModel):
    """Classify exactly one source: a saved test sample or a custom feature dictionary."""

    sample_index: Optional[int] = Field(
        None,
        ge=0,
        description="Index of a saved test sample, when local X_test.npy/y_test.npy exist.",
    )
    features: Optional[Dict[str, float]] = Field(
        None,
        description='Raw flow features, for example {"Dst Port": 80, "Flow Duration": 5000}.',
    )

    @model_validator(mode="after")
    def exactly_one_input(self):
        has_sample = self.sample_index is not None
        has_features = bool(self.features)
        if has_sample == has_features:
            raise ValueError("Send exactly one of sample_index or features.")
        return self


class AskRequest(BaseModel):
    """Natural-language question sent to the SentinelAI agent."""

    question: str = Field(
        ...,
        min_length=1,
        max_length=4000,
        description="Question in Arabic or English.",
    )
