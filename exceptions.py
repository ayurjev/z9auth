
""" Исключения """


class NoDataForAuth(Exception):
    """ Недостаточно данных для аутентификации """
    code = 1


class IncorrectToken(Exception):
    """ Некорректный токен """
    code = 2


class IncorrectPassword(Exception):
    """ Некорректный пароль """
    code = 3


class IncorrectLogin(Exception):
    """ Некорректный логин """
    code = 4


class NewPasswordsMismatch(Exception):
    """ Пароли не совпадают """
    code = 5


class VerificationTimeExceeded(Exception):
    """ Тайм-аут ожидания подтверждения email'a или номера телефона """
    code = 6


class IncorrectVerificationCode(Exception):
    """ Некорректный код верификации """
    code = 7


class IncorrectVerificationCodeFatal(Exception):
    """ Некорректный код верификации """
    code = 8


class IncorrectOAuthSignature(Exception):
    """ Некорректная подпись OAuth """
    code = 9


class NoSuchUser(Exception):
    """ Пользователь не найден """
    code = 10


class AlreadyRegistred(Exception):
    """ Уже зарегистрирован в системе """
    code = 11


class NoVerificationProcess(Exception):
    """ Верификация не начата """
    code = 12