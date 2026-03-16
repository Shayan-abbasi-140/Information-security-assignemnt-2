from presidio_analyzer import AnalyzerEngine, PatternRecognizer, Pattern
from presidio_anonymizer import AnonymizerEngine
import time

class LLMShield:
    def __init__(self, block_threshold=0.75, mask_confidence=0.65):
        self.analyzer = AnalyzerEngine()
        self.anonymizer = AnonymizerEngine()
        self.block_thresh = block_threshold
        self.mask_conf = mask_confidence
        self._setup_custom_recognizers()

    def _setup_custom_recognizers(self):
        # Customizations: AWS Token with context-aware scoring
        aws_pattern = Pattern(name="aws_token", regex=r"AKIA[0-9A-Z]{16}", score=0.5)
        aws_recognizer = PatternRecognizer(
            supported_entity="AWS_TOKEN",
            patterns=[aws_pattern],
            context=["aws", "token", "access", "secret"]
        )
        self.analyzer.registry.add_recognizer(aws_recognizer)

    def check_injection(self, prompt_text):
        """Calculates prompt injection risk."""
        malicious_terms = ["jailbreak", "ignore previous", "system prompt", "bypass rules", "admin mode"]
        risk = 0.0
        for term in malicious_terms:
            if term in prompt_text.lower():
                risk += 0.4
        return risk

    def process_request(self, prompt_text):
        """Main pipeline execution."""
        t0 = time.time()
        risk_score = self.check_injection(prompt_text)

        # Policy Decision: Block
        if risk_score >= self.block_thresh:
            return "BLOCKED", "Alert: Malicious prompt detected.", round((time.time() - t0) * 1000, 2)

        # Policy Decision: Mask (with confidence calibration)
        analysis_results = self.analyzer.analyze(
            text=prompt_text,
            entities=["PERSON", "EMAIL_ADDRESS", "PHONE_NUMBER", "AWS_TOKEN"],
            language='en'
        )
        filtered_results = [r for r in analysis_results if r.score >= self.mask_conf]

        if filtered_results:
            safe_text = self.anonymizer.anonymize(text=prompt_text, analyzer_results=filtered_results).text
            return "MASKED", safe_text, round((time.time() - t0) * 1000, 2)

        # Policy Decision: Allow
        return "ALLOWED", prompt_text, round((time.time() - t0) * 1000, 2)
