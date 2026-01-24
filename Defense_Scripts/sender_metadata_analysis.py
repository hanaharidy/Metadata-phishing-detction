import math
import re
from collections import Counter
from typing import Dict, List, Tuple, Optional


class SenderMetadataAnalyzer:
    def __init__(self, email_address: str, headers: Optional[Dict] = None,
                 weights: Tuple[float, float] = (0.7, 0.3)):
        """
        Initialize with sender email and optional headers for SPF/DKIM/DMARC.
        """
        if abs(sum(weights) - 1.0) > 0.001:
            raise ValueError(f"Weights must sum to 1.0, got {sum(weights)}")
        if any(w < 0 or w > 1 for w in weights):
            raise ValueError(f"Weights must be between 0 and 1, got {weights}")

        self.email_address = str(email_address).strip().lower()
        self.headers = headers if headers else {}
        self.weights = weights

        self.metadata = self.parse_email_identity(self.email_address)
        self.auth_results = self.parse_auth_results(self.headers)

        self.tier1_patterns = {
            "consecutive_digits": r"\d{3,}",
            "repeated_chars": r"(.)\1{2,}",
            "hyphen_clusters": r"-{2,}",
        }

    # ----------------------------
    # TIER 1: CRITICAL METADATA
    # ----------------------------
    @staticmethod
    def parse_email_identity(email_address: str) -> Dict:
        result = {
            "raw": email_address,
            "valid": False,
            "local_part": None,
            "domain": None,
            "tld": None,
            "domain_parts": [],
            "local_part_length": 0,
            "domain_length": 0,
            "tld_length": 0
        }

        if "@" not in email_address:
            return result

        local_part, domain = email_address.split("@", 1)
        if not local_part or not domain:
            return result

        domain_parts = domain.split(".")
        if len(domain_parts) < 2:
            return result

        tld = domain_parts[-1]
        if len(tld) < 1:
            return result

        result.update({
            "valid": True,
            "local_part": local_part,
            "domain": domain,
            "tld": tld,
            "domain_parts": domain_parts,
            "local_part_length": len(local_part),
            "domain_length": len(domain),
            "tld_length": len(tld)
        })

        return result

    @staticmethod
    def calculate_entropy(text: str) -> float:
        if not text:
            return 0.0
        counter = Counter(text)
        length = len(text)
        entropy = 0.0
        for count in counter.values():
            p = count / length
            entropy -= p * math.log2(p)
        return entropy

    def parse_auth_results(self, headers: Dict) -> Dict:
        auth_header = headers.get("Authentication-Results", "").lower()
        auth_header += " " + headers.get("Received-SPF", "").lower()

        result = {
            "spf": False,
            "dkim": False,
            "dmarc": False,
            "raw_header": auth_header,
            "has_authentication_header": bool(auth_header.strip())
        }

        result["spf"] = any(x in auth_header for x in ["spf=pass", "spf pass", "pass (spf)"])
        result["dkim"] = any(x in auth_header for x in ["dkim=pass", "dkim pass", "pass (dkim)"])
        result["dmarc"] = any(x in auth_header for x in ["dmarc=pass", "dmarc pass", "pass (dmarc)"])

        if "spf=fail" in auth_header or "spf fail" in auth_header:
            result["spf"] = False
        if "dkim=fail" in auth_header or "dkim fail" in auth_header:
            result["dkim"] = False
        if "dmarc=fail" in auth_header or "dmarc fail" in auth_header:
            result["dmarc"] = False

        return result

    # ----------------------------
    # TIER 2: IMPORTANT METADATA
    # ----------------------------
    def analyze_structural_metrics(self) -> Dict:
        metadata = self.metadata
        if not metadata["valid"]:
            return {"valid": False, "metrics": {}}

        domain = metadata["domain"]
        local_part = metadata["local_part"]
        tld = metadata["tld"]

        metrics = {
            "domain_length": metadata["domain_length"],
            "local_part_length": metadata["local_part_length"],
            "tld_length": metadata["tld_length"],
            "total_domain_parts": len(metadata["domain_parts"]),
            "domain_entropy": self.calculate_entropy(domain),
            "domain_hyphen_count": domain.count("-"),
            "domain_digit_count": sum(c.isdigit() for c in domain),
            "domain_digit_ratio": sum(c.isdigit() for c in domain) / len(domain),
            "local_digit_ratio": sum(c.isdigit() for c in local_part) / len(local_part),
            "local_dot_count": local_part.count("."),
            "has_consecutive_digits": bool(re.search(self.tier1_patterns["consecutive_digits"], domain)),
            "has_repeated_chars": bool(re.search(self.tier1_patterns["repeated_chars"], domain)),
            "tld_is_numeric": tld.isdigit()
        }

        return {"valid": True, "metrics": metrics}

    # ----------------------------
    # TIER 3: SUPPORTING METADATA
    # ----------------------------
    def analyze_supporting_metadata(self) -> Dict:
        metadata = self.metadata
        if not metadata["valid"]:
            return {"valid": False, "supporting_metrics": {}}

        domain = metadata["domain"]
        parts = metadata["domain_parts"]

        part_lengths = [len(p) for p in parts]
        variance = self._calculate_variance(part_lengths)

        char_dist = self._get_character_distribution(domain)

        supporting_metrics = {
            "avg_domain_part_length": sum(part_lengths) / len(part_lengths),
            "domain_part_variance": variance,
            "unique_chars_ratio": char_dist["unique_ratio"],
            "letter_ratio": char_dist["letter_ratio"],
            "special_char_ratio": char_dist["special_ratio"],
            "has_hyphen_clusters": bool(re.search(self.tier1_patterns["hyphen_clusters"], domain)),
            "is_alphanumeric_only": domain.replace(".", "").replace("-", "").isalnum()
        }

        return {"valid": True, "supporting_metrics": supporting_metrics}

    @staticmethod
    def _calculate_variance(numbers: List[float]) -> float:
        if len(numbers) < 2:
            return 0.0
        mean = sum(numbers) / len(numbers)
        return sum((x - mean) ** 2 for x in numbers) / len(numbers)

    @staticmethod
    def _get_character_distribution(text: str) -> Dict:
        letters = sum(c.isalpha() for c in text)
        digits = sum(c.isdigit() for c in text)
        special = len(text) - letters - digits

        return {
            "unique_ratio": len(set(text)) / len(text),
            "letter_ratio": letters / len(text),
            "digit_ratio": digits / len(text),
            "special_ratio": special / len(text)
        }

    # ----------------------------
    # RISK CALCULATION (TIERS 1–3)
    # ----------------------------
    def calculate_metadata_risk(self) -> Tuple[int, List[str]]:
        risk = 0
        reasons = []

        if not self.metadata["valid"]:
            return 100, ["TIER 1: Invalid email format"]

        structural = self.analyze_structural_metrics()
        supporting = self.analyze_supporting_metadata()

        m = structural["metrics"]
        s = supporting["supporting_metrics"]
        auth = self.auth_results

        if not auth["has_authentication_header"]:
            risk += 60
            reasons.append("TIER 1: No authentication header")
        else:
            if not auth["spf"]:
                risk += 40
                reasons.append("TIER 1: SPF failed")
            if not auth["dkim"]:
                risk += 30
                reasons.append("TIER 1: DKIM failed")
            if not auth["dmarc"]:
                risk += 30
                reasons.append("TIER 1: DMARC failed")

        if m["domain_entropy"] > 4.0:
            risk += 30
            reasons.append("TIER 1: High domain entropy")

        if m["domain_hyphen_count"] >= 3:
            risk += 30
            reasons.append("TIER 2: Many hyphens")

        if m["domain_digit_ratio"] > 0.5:
            risk += 35
            reasons.append("TIER 2: High digit ratio")

        if m["tld_is_numeric"]:
            risk += 40
            reasons.append("TIER 2: Numeric TLD")

        if s["has_hyphen_clusters"]:
            risk += 15
            reasons.append("TIER 3: Hyphen clusters")

        return max(0, min(risk, 100)), reasons

    # ----------------------------
    # FINAL COMBINED SCORE
    # ----------------------------
    def combined_risk_score(self) -> Dict:
        score, reasons = self.calculate_metadata_risk()

        if score >= 75:
            level = "HIGH"
        elif score >= 50:
            level = "MEDIUM"
        elif score >= 25:
            level = "LOW"
        else:
            level = "VERY LOW"

        return {
            "email": self.email_address,
            "final_score": score,
            "risk_level": level,
            "metadata_reasons": reasons,
            "auth_results": self.auth_results
        }

