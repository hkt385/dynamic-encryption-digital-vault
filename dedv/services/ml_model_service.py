"""Loads model/final_model.joblib once and runs inference. No UI code.

Schema comes from CONTEXT_PROMPT.md (sections 3, 5, 7) and was checked against the
fitted pipeline at load time: the 7 input columns, their valid values (read from the
fitted encoders, so they cannot drift from the model) and the 4 class labels.
Predictions are mapped by class NAME (`classes_`), never by numeric index.
"""
import threading
from dataclasses import dataclass
from pathlib import Path

from paths import model_path

# The model pickle references `dedv_ml.pipeline._AsString`; dedv/dedv_ml is a shim for it.
import dedv_ml.pipeline  # noqa: F401,E402

# Order shown in the UI (CONTEXT_PROMPT.md section 7, "K7").
FEATURES = ("Sensitivity", "Who Should Access", "Access Frequency", "Exposure Consequence",
            "Protection Duration", "Multiple Devices", "Multiple Locations/Countries")
ORDINAL_FEATURES = ("Sensitivity", "Access Frequency", "Exposure Consequence", "Protection Duration")
NOMINAL_FEATURES = ("Who Should Access", "Multiple Devices", "Multiple Locations/Countries")

CLASS_LABELS = ("Low", "Standard", "Enhanced", "High/Critical")   # fixed project order
CONFIDENCE_REVIEW_THRESHOLD = 0.70                                  # context section 9
# Validated Enhanced precision / recall of the K7 model (context section 7).
ENHANCED_VALIDATED_PRECISION = 0.10
ENHANCED_VALIDATED_RECALL = 0.10


class ModelError(Exception):
    """Model missing/incompatible/failed. Message is safe to show to the user."""


class ModelInputError(ModelError):
    """The supplied parameters do not match the model's schema."""


@dataclass(frozen=True)
class ModelPrediction:
    label: str                              # one of CLASS_LABELS
    confidence: float                       # probability of `label`
    probabilities: dict[str, float]         # by class name

    @property
    def review_required(self) -> bool:
        return self.confidence < CONFIDENCE_REVIEW_THRESHOLD


class MLModelService:
    def __init__(self, path: Path | None = None):
        self.path = Path(path) if path else model_path()
        self._model = None
        self._input_columns: list[str] = []
        self._options: dict[str, tuple[str, ...]] = {}
        self._classes: list[str] = []
        self._lock = threading.Lock()
        self._load()

    # ---- loading -------------------------------------------------------------------------
    def _load(self) -> None:
        if not self.path.is_file():
            raise ModelError(f"Prediction model not found: {self.path}")
        try:
            import joblib
            model = joblib.load(self.path)
        except Exception as e:      # unpickling can fail in many ways (version, missing class)
            raise ModelError(f"The prediction model could not be loaded: {type(e).__name__}: {e}") from e
        try:
            classes = [str(c) for c in model.classes_]
            columns = [str(c) for c in model.feature_names_in_]
            pre = model.named_steps["preprocess"]
            options: dict[str, tuple[str, ...]] = {}
            enc = pre.named_transformers_["ordinal"].named_steps["encode"]
            for name, cats in zip(pre.transformers_[0][2], enc.categories_):
                options[name] = tuple(str(c) for c in cats)
            onehot = pre.named_transformers_["nominal"].named_steps["onehot"]
            for name, cats in zip(pre.transformers_[1][2], onehot.categories_):
                options[name] = tuple(str(c) for c in cats)
        except (AttributeError, KeyError, IndexError) as e:
            raise ModelError(f"The prediction model has an unexpected structure: {e!r}") from e
        if sorted(classes) != sorted(CLASS_LABELS):
            raise ModelError(f"Unexpected model classes {classes}; expected {list(CLASS_LABELS)}.")
        missing = [f for f in FEATURES if f not in options or f not in columns]
        if missing:
            raise ModelError(f"The model does not use the expected inputs: {missing}")
        self._model, self._classes, self._input_columns, self._options = model, classes, columns, options

    # ---- schema --------------------------------------------------------------------------
    @property
    def classes(self) -> list[str]:
        return list(self._classes)

    def options(self, feature: str) -> tuple[str, ...]:
        return self._options[feature]

    def default_parameters(self) -> dict[str, str]:
        """A valid starting value for every input (middle option; 'No'/'Only me' for the flags)."""
        pick = {"Who Should Access": "Only me", "Multiple Devices": "No",
                "Multiple Locations/Countries": "No"}
        return {f: pick[f] if f in pick and pick[f] in self._options[f]
                else self._options[f][len(self._options[f]) // 2] for f in FEATURES}

    def validate(self, params: dict) -> dict[str, str]:
        """Return a clean copy or raise ModelInputError. Unknown values are rejected because
        the pipeline would otherwise silently impute (ordinals) or zero-encode (nominals) them."""
        if not isinstance(params, dict):
            raise ModelInputError("Parameters must be a mapping of input name to value.")
        absent = [f for f in FEATURES if f not in params]
        if absent:
            raise ModelInputError("Missing parameter(s): " + ", ".join(absent))
        extra = [k for k in params if k not in FEATURES]
        if extra:
            raise ModelInputError("Unknown parameter(s): " + ", ".join(map(str, extra)))
        clean = {}
        for f in FEATURES:
            v = params[f]
            if not isinstance(v, str) or v not in self._options[f]:
                raise ModelInputError(f"Invalid value {v!r} for '{f}'. "
                                      f"Allowed: {', '.join(self._options[f])}.")
            clean[f] = v
        return clean

    # ---- inference -----------------------------------------------------------------------
    def predict(self, params: dict) -> ModelPrediction:
        import pandas as pd
        clean = self.validate(params)
        # The model was fitted on 10 columns and drops 3 of them inside its ColumnTransformer;
        # those must exist by name but their values are never used.
        row = {c: clean.get(c, "") for c in self._input_columns}
        try:
            with self._lock:
                proba = self._model.predict_proba(pd.DataFrame([row], columns=self._input_columns))[0]
        except Exception as e:
            raise ModelError(f"Prediction failed: {type(e).__name__}: {e}") from e
        probs = {c: float(p) for c, p in zip(self._classes, proba)}
        label = max(probs, key=probs.get)
        return ModelPrediction(label, probs[label], probs)


_service: MLModelService | None = None
_service_lock = threading.Lock()


def get_model_service() -> MLModelService:
    """Process-wide instance: the model is loaded once, on first use."""
    global _service
    with _service_lock:
        if _service is None:
            _service = MLModelService()
        return _service
