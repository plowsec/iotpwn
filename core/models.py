from dataclasses import dataclass


@dataclass
class Function:
    name: str
    binary: str


@dataclass
class Binary:
    name: str
    imports: set
    exports: set
