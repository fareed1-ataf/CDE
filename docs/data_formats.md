# Data Formats and Schemas

## 1. Input Formats Supported
The `FileParser` handles the following input file types:
- **Documents:** `.pdf` (pypdf), `.docx` (python-docx)
- **Data:** `.xlsx` (openpyxl), `.csv` / `.tsv`
- **Binaries:** `.exe`, `.elf`, `.dll`, `.bin` (structural analysis and ASCII string extraction)
- **Archives:** `.zip` (file manifest extraction)
- **Source Code / Text:** UTF-8 auto-detected via heuristic binary scanning

## 2. Output Formats Generated

### Alpaca JSONL (`all_records.jsonl`)
Standard instruction-tuning format compatible with most finetuning frameworks.
```json
{
  "instruction": "Analyze the provided suspicious artifact and output your findings.",
  "input": "function eval_payload() { ... }",
  "output": "The provided code is an obfuscated JavaScript dropper..."
}
```

### Rich JSONL (`all_rich_records.jsonl`)
Contains extended metadata, quality scores, and routing reasoning for debugging.
```json
{
  "schema": "analysis",
  "task_type": "malware_analysis",
  "quality_score": 0.85,
  "source_file": "sample.js",
  "provider": "ollama",
  "alpaca": { ... },
  "rich_data": {
    "mitre_attack": ["T1059.007"],
    "ioc_extracted": ["192.168.1.50"]
  }
}
```

### LLaMA-3 ChatML Format
Exported via `/api/v1/export/llama3`. Directly embeds system prompts and uses LLaMA-3 special tokens.
```text
<|begin_of_text|><|start_header_id|>system<|end_header_id|>
You are an expert malware analyst...
<|eot_id|><|start_header_id|>user<|end_header_id|>
...
```

## 3. Supported Generative Schemas (Pydantic Models)
- `ChainOfThought`: Deep reasoning steps for logic-heavy datasets.
- `Analysis`: Structured intelligence reports.
- `QA`: Contextual question-answer pairs.
- `Chat`: Multi-turn simulated SOC investigations.
- `CodeGen`: Security tool generation.
- `CodeReview`: Vulnerability detection.
- `ToolUsage`: Function-calling and automated execution planning.
