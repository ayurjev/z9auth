
""" Exceptions """


class NoDataForAuth(Exception):
    """ Недостаточно данных для аутентификации """
    code = 1


class IncorrectToken(Exception):
    """ Недостаточно данных для аутентификации """
    code = 2


class IncorrectPassword(Exception):
    """ Недостаточно данных для аутентификации """
    code = 3


class IncorrectLogin(Exception):
    """ Недостаточно данных для аутентификации """
    code = 4


class NewPasswordsMismatch(Exception):
    """ Недостаточно данных для аутентификации """
    code = 5


class VerificationTimeExceeded(Exception):
    """ Недостаточно данных для аутентификации """
    code = 6


class IncorrectVerificationCode(Exception):
    """ Недостаточно данных для аутентификации """
    code = 7


class IncorrectVerificationCodeFatal(Exception):
    """ Недостаточно данных для аутентификации """
    code = 8


class IncorrectOAuthSignature(Exception):
    code = 9


class NoSuchUser(Exception):
    code = 10


class AlreadyRegistred(Exception):
    code = 11