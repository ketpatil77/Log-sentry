from abc import ABC, abstractmethod
from app.models.event import Event

class BaseParser(ABC):
    @abstractmethod
    def matches(self, lines: list[str]) -> bool: ...

    @abstractmethod
    def parse(self, line: str) -> Event | None: ...
