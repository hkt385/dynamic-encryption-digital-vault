"""PLACEHOLDER for the ML security decision engine. Makes no prediction."""
from dataclasses import dataclass
from pathlib import Path


@dataclass
class SecurityDecision:
    level: str | None      # None = engine not connected / no decision
    message: str = ""


class SecurityDecisionEngine:
    def decide(self, file_path: Path, account_type: str) -> SecurityDecision:
        # TODO: connect the ML model. It must return the final level label
        # (Personal: 3 levels; Enterprise: 5, with 4/5 shown as "High/Critical").
        return SecurityDecision(None, "Security decision engine not connected yet.")
