# Defense_Scripts/phishing_batch_evaluator.py

from .phishing_evaluator import PhishingMaxScoreEvaluator
import os
import pandas as pd

class PhishingBatchEvaluator(PhishingMaxScoreEvaluator):
    """
    Wrapper for batch evaluation using two Excel files.
    Inherits all methods from PhishingMaxScoreEvaluator.
    You can extend this class to add more batch-specific features if needed.
    """

    def __init__(self, file1: str, file2: str, column_name: str, threshold: float):
        """
        Initialize the batch evaluator.
        Args:
            file1: Path to first Excel file (model 1 scores)
            file2: Path to second Excel file (model 2 scores)
            column_name: Column containing phishing scores
            threshold: Score threshold to classify as PHISHING
        """
        super().__init__(file1=file1, file2=file2, column_name=column_name, threshold=threshold)

    def evaluate_and_save(self, output_dir: str, output_file: str = "evaluation_result.xlsx") -> str:
        """
        Run batch evaluation and save the results to Excel.
        Args:
            output_dir: Directory where results will be saved
            output_file: Name of the output Excel file
        Returns:
            Path to the saved Excel file
        """
        os.makedirs(output_dir, exist_ok=True)
        result_df = self.classify_rows()
        save_path = os.path.join(output_dir, output_file)
        result_df.to_excel(save_path, index=False)
        return save_path
