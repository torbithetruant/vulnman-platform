from typing import Optional

class RiskCalculator:
    """
    Calculates business risk based on technical CVSS scores and environmental context.
    """
    
    @staticmethod
    def calculate(
        cvss_score: float, 
        is_public_facing: bool = False,
        has_known_exploit: bool = False
    ) -> float:
        """
        Returns a risk score (0.0 - 10.0).
        
        Logic:
        - Base: CVSS Score
        - +1.0 if asset is Public Facing
        - +1.5 if there is a Known Exploit (Code Red!)
        - Cap at 10.0
        """
        risk = cvss_score
        
        # Contextual Adjustments
        if is_public_facing:
            risk += 1.0
            
        if has_known_exploit:
            risk += 1.5
            
        # Normalize to max 10.0
        return min(risk, 10.0)

    @staticmethod
    def get_severity_from_score(score: float) -> str:
        """Map numerical risk back to a label."""
        if score >= 9.0:
            return "CRITICAL"
        elif score >= 7.0:
            return "HIGH"
        elif score >= 4.0:
            return "MEDIUM"
        elif score > 0:
            return "LOW"
        return "INFO"