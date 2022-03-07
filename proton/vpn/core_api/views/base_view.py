from abc import ABC, abstractmethod


class BaseView(ABC):

    @abstractmethod
    def ask_for_login(self) -> str:
        pass

    @abstractmethod
    def ask_for_2fa(self) -> str:
        pass

    @abstractmethod
    def display_info(self, msg) -> None:
        print(msg)

    @abstractmethod
    def display_error(self, str):
        pass
