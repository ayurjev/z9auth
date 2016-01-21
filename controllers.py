""" Контроллеры сервиса """

import json
from envi import Controller, Request
from models import Credentials, AuthenticationService
from exceptions import BaseAuthException

service = AuthenticationService()


def error_format(func):
    """ Декоратор для обработки любых исключений возникающих при работе сервиса
    :param func:
    """
    def wrapper(*args, **kwargs):
        """ wrapper
        :param args:
        :param kwargs:
        """
        try:
            return func(*args, **kwargs)
        except BaseAuthException as e:
            return json.dumps({"error": {"code": e.code, "message": str(e)}})
    return wrapper


class AuthController(Controller):
    """ Контроллер """

    @classmethod
    def build_credentials(cls, request: Request):
        """ Метод для создания экземпляра класса Credentials на основе предоставленного объекта Request
        :param request:
        :return:
        """
        credentials = Credentials()
        credentials.email = request.get("email", None)
        credentials.phone = request.get("phone", None)
        credentials.token = request.get("token", None)
        credentials.password = request.get("password", None)
        credentials.vk_id = request.get("vk_id", None)
        return credentials

    @classmethod
    @error_format
    def register(cls, request: Request, **kwargs):
        """ Метод для регистрации новых учетных данных
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(service.register(cls.build_credentials(request)))

    @classmethod
    @error_format
    def authenticate(cls, request: Request, **kwargs):
        """ Метод для выполнения попытки аутентификации
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(service.authenticate(cls.build_credentials(request)))

    @classmethod
    @error_format
    def authenticate_vk(cls, request: Request, **kwargs):
        """ Метод для выполнения аутентификации через Вк
        :param request:
        :param kwargs:
        :return:
        """
        vk_data, sig = request.get("vk_concated_string"), request.get("signature")
        return json.dumps(service.authenticate_vk(cls.build_credentials(request), vk_data, sig))

    @classmethod
    @error_format
    def recover_password(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(service.recover_password(cls.build_credentials(request)))

    @classmethod
    @error_format
    def set_new_password(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(
            service.set_new_password(
                cls.build_credentials(request), request.get("current_password"),
                request.get("new_password"), request.get("new_password")
            )
        )

    @classmethod
    @error_format
    def set_new_email(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(service.set_new_email(cls.build_credentials(request), request.get("new_email")))

    @classmethod
    @error_format
    def set_new_phone(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(service.set_new_phone(cls.build_credentials(request), request.get("new_phone")))

    @classmethod
    @error_format
    def verify_email(cls, request: Request, **kwargs):
        """ Метод для подтверждения электронной почты
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(service.verify_email(cls.build_credentials(request), request.get("verification_code")))

    @classmethod
    @error_format
    def verify_phone(cls, request: Request, **kwargs):
        """ Метод для подтверждения номера телефона
        :param request:
        :param kwargs:
        :return:
        """
        return json.dumps(service.verify_phone(cls.build_credentials(request), request.get("verification_code")))