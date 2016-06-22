""" Контроллеры сервиса """

import os
import json
from envi import Controller, Request, microservice
from models import Credentials, AuthenticationService, normalize_phone_number
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
            return json.dumps(func(*args, **kwargs))
        except BaseAuthException as e:
            return json.dumps({"error": {"code": e.code, "message": e.msg}})
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
        credentials.email = request.get("email").lower() if request.get("email", None) else None
        credentials.phone = normalize_phone_number(request.get("phone")) if request.get("phone", False) else None
        credentials.token_name = request.get("token_name", "")
        credentials.token = request.get("%stoken" % credentials.token_name, None)
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
        return service.register(cls.build_credentials(request))

    @classmethod
    @error_format
    def authenticate(cls, request: Request, **kwargs):
        """ Метод для выполнения попытки аутентификации
        :param request:
        :param kwargs:
        :return:
        """
        return service.authenticate(cls.build_credentials(request))

    @classmethod
    @error_format
    def authenticate_vk(cls, request: Request, **kwargs):
        """ Метод для выполнения аутентификации через Вк
        :param request:
        :param kwargs:
        :return:
        """
        code = request.get("code")
        redirect_url = request.get("redirect_url", None)
        return service.authenticate_vk(cls.build_credentials(request), code, redirect_url)

    @classmethod
    @error_format
    def recover_password(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return service.recover_password(cls.build_credentials(request))

    @classmethod
    @error_format
    def set_new_password(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return service.set_new_password(
            cls.build_credentials(request), request.get("current_password"),
            request.get("new_password"), request.get("new_password2")
        )

    @classmethod
    @error_format
    def set_new_email(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return service.set_new_email(cls.build_credentials(request), request.get("new_email"))

    @classmethod
    @error_format
    def set_new_phone(cls, request: Request, **kwargs):
        """ Метод для восстановления пароля пользователя
        :param request:
        :param kwargs:
        :return:
        """
        return service.set_new_phone(cls.build_credentials(request), normalize_phone_number(request.get("new_phone")))

    @classmethod
    @error_format
    def verify_email(cls, request: Request, **kwargs):
        """ Метод для подтверждения электронной почты
        :param request:
        :param kwargs:
        :return:
        """
        return service.verify_email(cls.build_credentials(request), request.get("verification_code"))

    @classmethod
    @error_format
    def verify_phone(cls, request: Request, **kwargs):
        """ Метод для подтверждения номера телефона
        :param request:
        :param kwargs:
        :return:
        """
        return service.verify_phone(cls.build_credentials(request), request.get("verification_code"))

    @classmethod
    @error_format
    def get_credentials(cls, request: Request, **kwargs):
        """ Возвращает учетные данные по id
        :param request:
        :param kwargs:
        :return:
        """
        return service.get_credentials(request.get("uid"))

    @classmethod
    @error_format
    def delete_credentials(cls, request: Request, **kwargs):
        """ Удаляет учетные данные по id
        :param request:
        :param kwargs:
        :return:
        """
        return service.delete_credentials(request.get("uid"))

    @classmethod
    @error_format
    def get_account_if_exists(cls, request: Request, **kwargs):
        """ Возвращает учетные данные по email, телефону или другим параметрам если аккаунт существует
        :param request:
        :param kwargs:
        :return:
        """
        return service.get_account_if_exists(cls.build_credentials(request))

    @classmethod
    @error_format
    def get_vk_data(cls, request: Request, **kwargs):
        """ Возвращает идентификатор приложения ВК, если он сконфигурирован
        :param request:
        :param kwargs:
        :return:
        """
        return {"vk_data": {
            "vk_app_id": os.environ.get("VK_APP_ID"),
            "vk_redirect_uri": os.environ.get("VK_REDIRECT_URI")
        }}
