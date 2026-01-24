import json
from typing import Union, Dict
from Defense_Scripts.sender_metadata_analysis import SenderMetadataAnalyzer


def SenderChecker(email: str, headers: Union[str, Dict, None] = None):
    """
    Analyze ONE email sender metadata.

    Parameters:
        email   : sender email address (string)
        headers : dict OR JSON string OR None

    Returns:
        combined metadata risk result
    """

    try:
        # If headers are JSON string → convert to dict
        if isinstance(headers, str):
            headers = json.loads(headers)

        if headers is None:
            headers = {}

        analyzer = SenderMetadataAnalyzer(
            email_address=email,
            headers=headers
        )

        result = analyzer.combined_risk_score()
        return result

    except Exception as e:
        return {
            "error": str(e),
            "email": email
        }
