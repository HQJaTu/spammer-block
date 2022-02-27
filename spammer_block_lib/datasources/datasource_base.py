from abc import ABC, abstractmethod
from typing import Union


class DatasourceBase(ABC):

    @abstractmethod
    def lookup(self, asn: int) -> Union[None, dict]:
        pass
