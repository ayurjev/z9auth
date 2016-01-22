
""" Исключения """


class BaseAuthException(Exception):
    """ Базовый класс исключений """
    code = 0
    msg = "Неизвестная ошибка"


class NoDataForAuth(BaseAuthException):
    """ Недостаточно данных для аутентификации """
    code = 1
    msg = "Недостаточно данных для аутентификации"


class IncorrectToken(BaseAuthException):
    """ Некорректный токен """
    code = 2
    msg = "Некорректный токен"


class IncorrectPassword(BaseAuthException):
    """ Некорректный пароль """
    code = 3
    msg = "Некорректный пароль"


class IncorrectLogin(BaseAuthException):
    """ Некорректный логин """
    code = 4
    msg = "Некорректный логин"


class NewPasswordsMismatch(BaseAuthException):
    """ Пароли не совпадают """
    code = 5
    msg = "Пароли не совпадают"


class VerificationTimeExceeded(BaseAuthException):
    """ Тайм-аут ожидания подтверждения email'a или номера телефона """
    code = 6
    msg = "Недостаточно данных для аутентификации"


class IncorrectVerificationCode(BaseAuthException):
    """ Некорректный код верификации """
    code = 7
    msg = "Некорректный код верификации"


class IncorrectVerificationCodeFatal(BaseAuthException):
    """ Некорректный код верификации """
    code = 8
    msg = "Некорректный код верификации"


class IncorrectOAuthSignature(BaseAuthException):
    """ Некорректная подпись OAuth """
    code = 9
    msg = "Некорректная подпись OAuth"


class NoSuchUser(BaseAuthException):
    """ Пользователь не найден """
    code = 10
    msg = "Пользователь не найден"


class AlreadyRegistred(BaseAuthException):
    """ Уже зарегистрирован в системе """
    code = 11
    msg = "Уже зарегистрирован в системе"


class NoVerificationProcess(BaseAuthException):
    """ Верификация не начата """
    code = 12
    msg = "Верификация не начата"


class InvalidPhoneNumber(BaseAuthException):
    """ Некорректный формат номера телефона """
    code = 13
    msg = "Некорректный формат номера телефона"