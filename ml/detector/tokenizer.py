"""
Code Tokenizer for ZeroSentinel.

Splits source code into lexical and semantic tokens:
- Decomposes snake_case and camelCase identifiers into subwords while retaining the full identifier.
- Retains operators, delimiters, and assignment tokens.
- Captures critical call sequences and string literal patterns.
"""

import re
from typing import List

# Regular expression to extract tokens: identifiers, operators, strings, calls
TOKEN_PATTERN = re.compile(
    r"[a-zA-Z_][a-zA-Z0-9_\.]*"              # Identifiers and dotted calls (e.g. cursor.execute, os.system)
    r"|==|!=|<=|>=|\+=|-=|\*=|/=|%=|\*\*|//" # Compound operators
    r"|[+\-*/%<>&|^~!=]"                     # Single operators
    r"|'[^'\n]*'|\"[^\"\n]*\""               # Short string literals
)

# Regex for camelCase splitting
CAMEL_CASE_SPLIT = re.compile(r"([a-z0-9])([A-Z])")

def split_identifier(identifier: str) -> List[str]:
    """Splits an identifier on dots, underscores, and camelCase boundaries."""
    subwords = set()
    parts = identifier.replace(".", "_").split("_")
    for part in parts:
        if not part:
            continue
        subwords.add(part.lower())
        # Check camelCase
        split_camel = CAMEL_CASE_SPLIT.sub(r"\1 \2", part).split()
        for cword in split_camel:
            if cword:
                subwords.add(cword.lower())
    return list(subwords)

def tokenize_code(code_text: str) -> List[str]:
    """
    Main tokenizer function used by TfidfVectorizer and line attribution.
    """
    if not code_text or not isinstance(code_text, str):
        return []

    raw_tokens = TOKEN_PATTERN.findall(code_text)
    tokens: List[str] = []

    for token in raw_tokens:
        tokens.append(token.lower())
        # If it's an identifier with underscores, dots, or camelCase, add subwords
        if any(c.isalpha() for c in token) and ("_" in token or "." in token or any(c.isupper() for c in token)):
            tokens.extend(split_identifier(token))

    return tokens
