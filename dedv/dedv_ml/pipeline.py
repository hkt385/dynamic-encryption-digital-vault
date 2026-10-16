"""Copy of the training pipeline's `_AsString` transformer (needed to unpickle the model)."""
import numpy as np
from sklearn.base import BaseEstimator


class _AsString(BaseEstimator):
    """Cast nominal columns to str so Scenario 3 and "3" encode identically."""

    def fit(self, X, y=None):
        return self

    def transform(self, X):
        import pandas as pd
        return pd.DataFrame(X).astype(str).to_numpy()

    def get_feature_names_out(self, input_features=None):
        return np.asarray(input_features)
