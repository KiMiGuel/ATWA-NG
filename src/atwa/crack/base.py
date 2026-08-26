"""Cracker abstract base class: crack(hashfile, wordlist) -> recovered passwords."""

from __future__ import annotations

from abc import ABC, abstractmethod


class Cracker(ABC):
    """Swappable cracking engine interface."""

    @abstractmethod
    def crack(self, hashfile: str, wordlist: str) -> dict[str, str]:
        """Crack hashfile with wordlist; return {hash_id: plaintext}."""
