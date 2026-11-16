"""Security-level decision: ML prediction + account-type rules. No UI code.

The model predicts one of Low / Standard / Enhanced / High/Critical from the 7 survey-style
parameters. It never inspects the file, so every file in a batch gets the same prediction for
the same parameters; the file path is kept in the interface as the integration point.

Account rules (enforced here and again in VaultService, not just hidden in the UI):
  * Personal   - final level must be Low, Standard or Enhanced. A High/Critical prediction is
                 NOT converted: the model is a 4-class model, and taking the best of the other
                 three probabilities would be an unvalidated decision rule, so no level is
                 assigned (status UNSUPPORTED).
  * Enterprise - Low / Standard / Enhanced are final. High/Critical needs an explicit user
                 choice of High or Critical (status CHOICE_REQUIRED until chosen).
The High / Critical choice only records the intended configuration; nothing is encrypted here.
"""
from dataclasses import dataclass, field
from pathlib import Path

from services.ml_model_service import (ENHANCED_VALIDATED_PRECISION, ENHANCED_VALIDATED_RECALL,
                                       MLModelService, ModelError, get_model_service)

PERSONAL = "Personal"
ENTERPRISE = "Enterprise"
HIGH_CRITICAL = "High/Critical"

PERSONAL_LEVELS = ("Low", "Standard", "Enhanced")
ENTERPRISE_PREDICTIONS = ("Low", "Standard", "Enhanced", HIGH_CRITICAL)
ENTERPRISE_FINAL_LEVELS = ("Low", "Standard", "Enhanced", "High", "Critical")

# Intended configurations only; no quantum-resistant encryption is implemented by choosing Critical.
HIGH_CRITICAL_OPTIONS = {
    "High": ("Less storage space", "Intended configuration: non-quantum encryption."),
    "Critical": ("More storage space", "Intended configuration: quantum-oriented encryption."),
}

FINAL = "final"
CHOICE_REQUIRED = "choice_required"
UNSUPPORTED = "unsupported"
ERROR = "error"


@dataclass
class SecurityDecision:
    status: str
    account_type: str
    predicted: str | None = None          # raw model label
    level: str | None = None              # final level; None until final
    message: str = ""
    confidence: float | None = None
    probabilities: dict = field(default_factory=dict)
    params: dict = field(default_factory=dict)   # parameters this prediction was made with
    notes: list = field(default_factory=list)    # review-required / Enhanced reliability warnings

    @property
    def is_final(self) -> bool:
        return self.status == FINAL and self.level is not None

    def choose_high_critical(self, choice: str) -> None:
        """Finalise an Enterprise High/Critical prediction as High or Critical."""
        if self.status != CHOICE_REQUIRED or self.account_type != ENTERPRISE:
            raise ValueError("No High/Critical choice is pending for this prediction.")
        if choice not in HIGH_CRITICAL_OPTIONS:
            raise ValueError(f"Invalid choice {choice!r}; expected 'High' or 'Critical'.")
        self.level, self.status = choice, FINAL
        self.message = f"Predicted High/Critical; you selected {choice}."


def validate_final_level(account_type: str, level: str | None) -> None:
    """Raise ValueError unless `level` may be stored for this account type."""
    allowed = {PERSONAL: PERSONAL_LEVELS, ENTERPRISE: ENTERPRISE_FINAL_LEVELS}.get(account_type)
    if allowed is None:
        raise ValueError(f"Unknown account type {account_type!r}.")
    if level not in allowed:
        raise ValueError(f"'{level}' is not an allowed security level for a {account_type} account.")


class SecurityDecisionEngine:
    def __init__(self, model: MLModelService | None = None):
        self._model = model
        self.load_error = ""
        if model is None:
            try:
                self._model = get_model_service()
            except ModelError as e:
                self.load_error = str(e)

    @property
    def model(self) -> MLModelService | None:
        return self._model

    def decide(self, file_path: Path, account_type: str, params: dict) -> SecurityDecision:
        """Never raises for model/input problems: returns status ERROR with a message."""
        if account_type not in (PERSONAL, ENTERPRISE):
            return SecurityDecision(ERROR, account_type, message=f"Unknown account type '{account_type}'.")
        if self._model is None:
            return SecurityDecision(ERROR, account_type, message=self.load_error or "Model not loaded.")
        try:
            clean = self._model.validate(params)
            pred = self._model.predict(clean)
        except ModelError as e:
            return SecurityDecision(ERROR, account_type, params=dict(params), message=str(e))

        d = SecurityDecision(FINAL, account_type, predicted=pred.label, confidence=pred.confidence,
                             probabilities=pred.probabilities, params=clean)
        if pred.review_required:
            d.notes.append(f"REVIEW REQUIRED: model confidence {pred.confidence:.0%} is below 70%.")
        if pred.label == "Enhanced":
            d.notes.append(f"Enhanced is not reliably predicted (validated precision "
                           f"{ENHANCED_VALIDATED_PRECISION:.2f}, recall {ENHANCED_VALIDATED_RECALL:.2f}).")

        if pred.label == HIGH_CRITICAL:
            if account_type == PERSONAL:
                d.status = UNSUPPORTED
                d.message = ("The model predicts High/Critical, which Personal accounts do not offer. "
                             "No level was assigned; a compatible three-level model is required.")
            else:
                d.status = CHOICE_REQUIRED
                d.message = "Predicted High/Critical: choose High or Critical."
        else:
            d.level = pred.label
            d.message = f"Predicted {pred.label}."
        if d.level is not None:
            validate_final_level(account_type, d.level)
        return d
