import sys
import os

# Add parent directory so imports work
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from Defense_Scripts.phishing_batch_evaluator import PhishingBatchEvaluator

def main():
    BASE_DIR = r"/Users/hanatarek/Downloads/denv 2/denv/dataset"

    FILE_1 = os.path.join(BASE_DIR, "email_predictions.xlsx")
    FILE_2 = os.path.join(BASE_DIR, "phishing_predictions.xlsx")

    OUTPUT_DIR = os.path.join(BASE_DIR, "evaluation_results")
    OUTPUT_FILE = "evaluation_result.xlsx"

    COLUMN_NAME = "phishing_score"
    THRESHOLD = 0.7

    evaluator = PhishingBatchEvaluator(
        file1=FILE_1,
        file2=FILE_2,
        column_name=COLUMN_NAME,
        threshold=THRESHOLD
    )

    output_path = evaluator.save_results(
        output_dir=OUTPUT_DIR,
        output_file=OUTPUT_FILE
    )

    print("✅ Evaluation completed successfully")
    print(f"📁 Output saved at: {output_path}")


if __name__ == "__main__":
    main()
