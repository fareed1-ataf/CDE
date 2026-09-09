import re
from dataclasses import dataclass

@dataclass
class ContentDimensions:
    """Quantitative measurement of content richness along specific dimensions."""
    code_volume: float        # 0.0 to 1.0
    semantic_density: float   # 0.0 to 1.0
    structural_complexity: float # 0.0 to 1.0
    overall_richness: float   # 0.0 to 1.0

class DeepContentAnalyzer:
    """
    Analyzes the 'richness' of content to determine how many angles/skills
    it can support. A highly rich file supports up to 4-5 schemas, while a
    simple one-liner only supports 1 or 2.
    """
    
    def analyze(self, content: str, filename: str) -> ContentDimensions:
        from pathlib import Path
        ext = Path(filename).suffix.lower()
        
        code_vol = self._estimate_code_volume(content, ext)
        sem_den = self._estimate_semantic_density(content)
        struct_comp = self._estimate_structural_complexity(content)
        
        # Weighted overall richness
        overall = (code_vol * 0.4) + (sem_den * 0.4) + (struct_comp * 0.2)
        
        return ContentDimensions(
            code_volume=code_vol,
            semantic_density=sem_den,
            structural_complexity=struct_comp,
            overall_richness=min(overall, 1.0)
        )

    def _estimate_code_volume(self, text: str, ext: str) -> float:
        if not text:
            return 0.0
            
        _CODE_EXTS = {'.py','.js','.c','.cpp','.go','.rs','.ps1','.sh','.php','.java'}
        if ext in _CODE_EXTS:
            # If it's a known code extension, baseline is high
            return 0.85
            
        # Heuristics for inline code in text/markdown
        code_lines = 0
        lines = text.splitlines()
        for line in lines:
            if re.search(r'[{};=()]|def\s+|class\s+|fn\s+|import\s+|let\s+|var\s+', line):
                code_lines += 1
                
        ratio = code_lines / max(len(lines), 1)
        return min(ratio * 1.5, 1.0)  # scale up

    def _estimate_semantic_density(self, text: str) -> float:
        if not text:
            return 0.0
        # Unique words vs total words (up to a cap)
        words = re.findall(r'\b\w+\b', text.lower())
        if not words:
            return 0.0
            
        unique_words = len(set(words))
        # A file with 300+ unique words is very semantically dense
        return min(unique_words / 300.0, 1.0)

    def _estimate_structural_complexity(self, text: str) -> float:
        if not text:
            return 0.0
        # Count headers, functions, classes
        headers = len(re.findall(r'^#+\s+', text, re.M))
        funcs_classes = len(re.findall(r'\b(?:def|class|function|fn|struct|interface)\s+\w+', text))
        lists = len(re.findall(r'^\s*[-*]\s+', text, re.M))
        
        score = (headers * 0.1) + (funcs_classes * 0.15) + (lists * 0.05)
        return min(score, 1.0)
