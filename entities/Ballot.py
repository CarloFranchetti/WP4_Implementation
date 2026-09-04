"""
Ballot — scheda elettorale per referendum (SI / NO / ASTENUTO).

Codifica del voto:
  v =  1  →  "SI"
  v =  0  →  "NO"
  v = -1  →  "ASTENUTO" (voto non espresso)
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Optional

VALID_CHOICES = {"SI", "NO", "ASTENUTO"}
REFERENDUM_QUESTION = "Sei favorevole alla proposta di legge X?"

# Mappatura scelta → valore intero binario
_CHOICE_TO_VALUE = {"SI": 1, "NO": 0, "ASTENUTO": -1}
_VALUE_TO_CHOICE = {v: k for k, v in _CHOICE_TO_VALUE.items()}
VALID_VOTE_VALUES = frozenset(_CHOICE_TO_VALUE.values())  # {1, 0, -1}


@dataclass
class Ballot:
    """Rappresenta una scheda di voto per un referendum SI/NO/ASTENUTO.

    Attributes:
        question: Il quesito referendario (fisso per tutta la sessione di voto).
        choice:   La scelta dell'elettore; None = scheda vuota (blank),
                  "SI", "NO" o "ASTENUTO" = scheda compilata.
    """

    question: str = REFERENDUM_QUESTION
    choice: Optional[str] = None  # None = blank ballot

    # ------------------------------------------------------------------
    # Metodi di serializzazione
    # ------------------------------------------------------------------

    def to_bytes(self) -> bytes:
        """Serializza la scheda in JSON (UTF-8)."""
        return json.dumps({"question": self.question, "choice": self.choice}).encode()

    @classmethod
    def from_bytes(cls, data: bytes) -> "Ballot":
        """Deserializza da JSON."""
        d = json.loads(data.decode())
        return cls(question=d["question"], choice=d.get("choice"))

    # ------------------------------------------------------------------
    # Vote value encoding
    # ------------------------------------------------------------------

    def to_vote_value(self) -> int:
        """Converte la scelta in valore intero v ∈ {1, 0, -1}.

        Mappatura:
          "SI"       ->  1
          "NO"       ->  0
          "ASTENUTO" -> -1
          None       -> -1  (scheda vuota = voto non espresso)

        Raises:
            ValueError: se choice non è una scelta valida.
        """
        if self.choice is None:
            return -1
        if self.choice not in _CHOICE_TO_VALUE:
            raise ValueError(f"Scelta non riconosciuta: '{self.choice}'")
        return _CHOICE_TO_VALUE[self.choice]

    @staticmethod
    def choice_from_value(value: int) -> str:
        """Converte un valore intero v nella scelta corrispondente.

        Raises:
            ValueError: se il valore non è in {1, 0, -1}.
        """
        if value not in _VALUE_TO_CHOICE:
            raise ValueError(f"Valore di voto non valido: {value} (atteso ∈ {{1, 0, -1}})")
        return _VALUE_TO_CHOICE[value]

    # ------------------------------------------------------------------
    # Validation
    # ------------------------------------------------------------------

    def is_blank(self) -> bool:
        return self.choice is None

    def is_valid(self) -> bool:
        """Una scheda compilata è valida se la scelta è SI, NO o ASTENUTO."""
        return self.choice in VALID_CHOICES
