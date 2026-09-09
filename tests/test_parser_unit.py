import pytest
import os
from shared_lib.parser import FileParser

@pytest.fixture
def parser():
    return FileParser(chunk_size=100, overlap=10)

@pytest.mark.unit
def test_parser_chunking_semantic(parser):
    # Normal case: semantic boundaries (Python functions)
    content = "def func1():\n    pass\n\ndef func2():\n    pass"
    chunks = parser.chunk(content)
    assert len(chunks) >= 1
    assert "def func1()" in chunks[0]

@pytest.mark.unit
def test_parser_empty_input(parser):
    # Edge case: empty input
    assert parser.chunk("") == []

@pytest.mark.unit
def test_parser_oversized_minified_string(parser):
    # Edge case: single line longer than 2x chunk_size (forces fallback to _force_split)
    content = "a" * 500
    chunks = parser.chunk(content)
    assert len(chunks) > 1
    # Check that chunks are roughly chunk_size
    assert len(chunks[0]) <= 110
