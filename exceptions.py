
""" Исключения """


class BaseAuthException(Exception):
    """ Базовый класс исключений """
    code = 0


class NoDataForAuth(BaseAuthException):
    """ Недостаточно данных для аутентификации """
    code = 1


class IncorrectToken(BaseAuthException):
    """ Некорректный токен """
    code = 2


class IncorrectPassword(BaseAuthException):
    """ Некорректный пароль """
    code = 3


class IncorrectLogin(BaseAuthException):
    """ Некорректный логин """
    code = 4


class NewPasswordsMismatch(BaseAuthException):
    """ Пароли не совпадают """
    code = 5


class VerificationTimeExceeded(BaseAuthException):
    """ Тайм-аут ожидания подтверждения email'a или номера телефона """
    code = 6


class IncorrectVerificationCode(BaseAuthException):
    """ Некорректный код верификации """
    code = 7


class IncorrectVerificationCodeFatal(BaseAuthException):
    """ Некорректный код верификации """
    code = 8


class IncorrectOAuthSignature(BaseAuthException):
    """ Некорректная подпись OAuth """
    code = 9


class NoSuchUser(BaseAuthException):
    """ Пользователь не найден """
    code = 10


class AlreadyRegistred(BaseAuthException):
    """ Уже зарегистрирован в системе """
    code = 11


class NoVerificationProcess(BaseAuthException):
    """ Верификация не начата """
    code = 12