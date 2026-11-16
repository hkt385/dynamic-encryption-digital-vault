"""Minimal shim so final_model.joblib can be unpickled.

The model was trained in a separate project whose pipeline referenced
`dedv_ml.pipeline._AsString`. Only that helper class is reproduced here, exactly
as in the training code; no training code lives in this application.
"""
