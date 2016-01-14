

class NoDataForAuth(Exception):
    code = 1


class IncorrectToken(Exception):
    code = 2


class IncorrectPassword(Exception):
    code = 3


class IncorrectLogin(Exception):
    code = 4


class NewPasswordsMismatch(Exception):
    code = 5


class VerificationTimeExceeded(Exception):
    code = 6


class IncorrectVerificationCode(Exception):
    code = 7


class IncorrectVerificationCodeFatal(Exception):
    code = 8


class IncorrectOAuthSignature(Exception):
    code = 9


class NoSuchUser(Exception):
    code = 10


class AlreadyRegistred(Exception):
    code = 11