import pandas as pd
from typing import Tuple


class RecipientRoleRisk:
    def __init__(
        self,
        email_address: str,
        employee_db: pd.DataFrame,
        weights: Tuple[float, float, float, float] = (0.4, 0.3, 0.2, 0.1)
    ):
        """
        Calculate recipient-based phishing risk using employee role metadata.

        Parameters
        ----------
        email_address : str
            Recipient email address to look up
        employee_db : pd.DataFrame
            Predefined employee database with column:
            ['emp_email', 'access_level', 'dept_sensitivity', 'target_history', 'exposure']
        weights : tuple
            Contribution of each factor
        """
        if abs(sum(weights) - 1.0) > 0.01:
            raise ValueError("Weights must sum to 1.0")

        self.email_address = email_address.lower().strip()
        self.employee_db = employee_db
        self.weights = weights


    def _lookup_employee(self):
        """
        Search employee database by emp_email
        """
        row = self.employee_db[
            self.employee_db["emp_email"].str.lower() == self.email_address
        ]

        if row.empty:
            return None

        return row.iloc[0].to_dict()

    def calculate_risk(self) -> int:
        """
        Calculate dynamic role-based phishing risk (0–100)
        """
        db_data = self._lookup_employee()

        # Fallback for unknown employees
        if not db_data:
            db_data = {
                "access_level": 40,
                "dept_sensitivity": 40,
                "target_history": 0,
                "exposure": 50
            }

        w1, w2, w3, w4 = self.weights

        score = (
            db_data["access_level"] * w1 +
            db_data["dept_sensitivity"] * w2 +
            db_data["target_history"] * w3 +
            db_data["exposure"] * w4
        )

        return int(min(score, 100))

