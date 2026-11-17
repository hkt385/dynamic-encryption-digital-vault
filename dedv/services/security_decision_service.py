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
Upward-only override: once a level is final the user may raise it, never lower it below the
prediction (High/Critical counts as High). Predictions with confidence below 70 % or of the
unreliable Enhanced class must be acknowledged before they can be stored. VaultService enforces
both rules again, so the UI cannot bypass them. Nothing is encrypted in this module.
"""
from dataclasses import dataclass, field
from pathlib import Path

from services.ml_model_service import (CONFIDENCE_REVIEW_THRESHOLD, ENHANCED_VALIDATED_PRECISION,
                                       ENHANCED_VALIDATED_RECALL, MLModelService, ModelError,
                                       get_model_service)

PERSONAL = "Personal"
ENTERPRISE = "Enterprise"
HIGH_CRITICAL = "High/Critical"

PERSONAL_LEVELS = ("Low", "Standard", "Enhanced")
ENTERPRISE_PREDICTIONS = ("Low", "Standard", "Enhanced", HIGH_CRITICAL)
ENTERPRISE_FINAL_LEVELS = ("Low", "Standard", "Enhanced", "High", "Critical")
LEVEL_ORDER = ENTERPRISE_FINAL_LEVELS     # lowest to highest
UNRELIABLE_CLASS = "Enhanced"             # validated precision and recall about 0.10

# What each choice does (services.encryption_service.LEVEL_ALGORITHM). Critical adds a post-quantum
# key encapsulation; that alone does not make the file "quantum-resistant".
HIGH_CRITICAL_OPTIONS = {
    "High": ("Less storage space", "ChaCha20-Poly1305 with a 256-bit key."),
    "Critical": ("More storage space",
                 "AES-256-GCM; the file key is encapsulated with ML-KEM-1024 (FIPS 203)."),
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
    acknowledged: bool = False                   # the user confirmed a prediction that needs review

    @property
    def is_final(self) -> bool:
        return self.status == FINAL and self.level is not None

    @property
    def needs_ack(self) -> bool:
        """Low confidence or the unreliable Enhanced class: the user must acknowledge it."""
        return (self.predicted == UNRELIABLE_CLASS or
                (self.confidence is not None and self.confidence < CONFIDENCE_REVIEW_THRESHOLD))

    @property
    def override(self) -> bool:
        return is_override(self.predicted, self.level)

    def raise_level(self, level: str) -> None:
        """Change the final level; anything allowed for the account and not below the prediction."""
        if not self.is_final:
            raise ValueError("This prediction has no final level yet.")
        validate_final_level(self.account_type, level)
        validate_not_below(self.predicted, level)
        self.level = level

    def choose_high_critical(self, choice: str) -> None:
        """Finalise an Enterprise High/Critical prediction as High or Critical."""
        if self.status != CHOICE_REQUIRED or self.account_type != ENTERPRISE:
            raise ValueError("No High/Critical choice is pending for this prediction.")
        if choice not in HIGH_CRITICAL_OPTIONS:
            raise ValueError(f"Invalid choice {choice!r}; expected 'High' or 'Critical'.")
        self.level, self.status = choice, FINAL
        self.message = f"Predicted High/Critical; you selected {choice}."


def account_levels(account_type: str) -> tuple[str, ...]:
    """Final levels an account may use: Personal never gets High or Critical."""
    return {PERSONAL: PERSONAL_LEVELS, ENTERPRISE: ENTERPRISE_FINAL_LEVELS}.get(account_type, ())


def validate_final_level(account_type: str, level: str | None) -> None:
    """Raise ValueError unless `level` may be stored for this account type."""
    allowed = account_levels(account_type)
    if not allowed:
        raise ValueError(f"Unknown account type {account_type!r}.")
    if level not in allowed:
        raise ValueError(f"'{level}' is not an allowed security level for a {account_type} account.")


def floor_level(predicted: str | None) -> str | None:
    """Lowest final level a prediction allows (High/Critical -> High); None if there is none."""
    if predicted == HIGH_CRITICAL:
        return "High"
    return predicted if predicted in LEVEL_ORDER else None


def is_below(level: str, floor: str | None) -> bool:
    return floor is not None and LEVEL_ORDER.index(level) < LEVEL_ORDER.index(floor)


def validate_not_below(predicted: str | None, level: str, floor: str | None = None) -> None:
    """Raise ValueError if `level` is below the floor (default: the prediction's floor)."""
    floor = floor or floor_level(predicted)
    if is_below(level, floor):
        what = (f"the predicted level {predicted}" if floor_level(predicted) == floor
                else f"the current level {floor} (no prediction was recorded for this file)")
        raise ValueError(f"{level} is below {what}. The security level may be raised but not lowered.")


def is_override(predicted: str | None, level: str | None) -> bool:
    """True if the final level differs from the prediction. Choosing High or Critical for a
    High/Critical prediction is the required choice, not an override; any other level is one
    (only a 0.1 vault can hold a level below its prediction)."""
    if level is None or floor_level(predicted) is None:
        return False
    return level not in (("High", "Critical") if predicted == HIGH_CRITICAL else (predicted,))


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
            d.notes.append(f"Review required: model confidence {pred.confidence:.0%} is below 70%.")
        if pred.label == "Enhanced":
            d.notes.append(f"Enhanced is not reliably predicted (validated precision "
                           f"{ENHANCED_VALIDATED_PRECISION:.2f}, recall {ENHANCED_VALIDATED_RECALL:.2f}).")

        if pred.label == HIGH_CRITICAL:
            if account_type == PERSONAL:
                d.status = UNSUPPORTED
                d.message = ("The model predicts High/Critical, which Personal accounts do not offer. "
                             "No level was assigned. To store it at High or Critical, use an "
                             "Enterprise vault (account type in Settings).")
            else:
                d.status = CHOICE_REQUIRED
                d.message = "Predicted High/Critical: choose High or Critical."
        else:
            d.level = pred.label
            d.message = f"Predicted {pred.label}."
        if d.level is not None:
            validate_final_level(account_type, d.level)
        return d
