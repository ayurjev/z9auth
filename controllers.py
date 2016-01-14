"""
    Contrllers for
    Authentification service z9auth
"""

from datetime import datetime, timedelta
from envi import Controller, Request, Application




class AuthController(Controller):
    """ AuthController """

    @classmethod
    def authentificate(cls, request: Request):
        """
        Выполняет аутентификацию пользователя по переданному объекту Request
        :param request: Запрос пользователя
        :return:
        """

        if request.get("login", False) and request.get("login"):
            return AuthentificationService.authentificate(
                (request.get("login"), request.get("password")), request.get("token", False)
            )
        elif request.get("phone", False) and request.get("phone") and request.get("password", False) and request.get("password"):
            phone = request.get("phone").replace(" ", "").replace("(", "").replace(")", "").replace("-", "")
            return AuthentificationService.authentificate(
                (phone, request.get("password")), request.get("token", False)
            )
        else:
            return AuthentificationService.authentificate(
                token=request.get("token", False)
            )

    @classmethod
    def auth(cls, request: Request, **kwargs) -> bool:
        try:
            user = cls.authentificate_by_request(request)
            if user:
                request.response.set_cookie(
                    "token", user.set_new_token() if not request.get("use_prev_token", False) else user.token,
                    path="/", expires=datetime.now() + timedelta(days=30)
                )
                return {"redirect_to": cls.root} if not request.get("use_prev_token", False) else True
        except (NoDataForAuth, IncorrectToken) as err:
            request.response.set_cookie(
                "token", "", path="/", expires=datetime.now() - timedelta(seconds=30*60)
            )
            raise err

    @classmethod
    def unauth(cls, app: Application, request: Request, **kwargs) -> bool:
        request.response.set_cookie("token", "", path="/", expires=datetime.now() - timedelta(seconds=30*60))
        app.redirect(cls.root)

    @classmethod
    def change_password(cls, request: Request, **kwargs):
        return AuthentificationService.change_password(request.get("login"))

    @classmethod
    def set_new_password(cls, user, request: Request, host, **kwargs):
        return AuthentificationService.set_new_password(
            user, request.get("current_password"),
            request.get("new_password"), request.get("new_password2")
        )

    @classmethod
    def check_phone_registration(cls, user, request: Request, **kwargs):
        return AuthentificationService.check_phone_registration(Phone(request.get("phone")).get_value())

    @classmethod
    def send_email_verification_code(cls, user, request: Request, **kwargs):
        return AuthentificationService.send_email_verification_code(user, request.get("email"))

    @classmethod
    def register(cls, user, request: Request, **kwargs):
        registred_user = AuthentificationService.register(
            user, request.get("email"), request.get("email_verification_code"), request.get("password")
        )
        if registred_user:
            request.response.set_cookie(
                "token", registred_user.set_new_token() if not request.get("use_prev_token", False) else registred_user.token,
                path="/", expires=datetime.now() + timedelta(days=30)
            )
            return {"redirect_to": cls.root} if not user or user.id != registred_user.id else True

    @classmethod
    def send_phone_verification_code(cls, user, request: Request, **kwargs):
        return AuthentificationService.send_phone_verification_code(user, Phone(request.get("phone")).get_value())

    @classmethod
    def verify_phone(cls, user, request: Request, **kwargs):
        return AuthentificationService.verify_phone(
            user, Phone(request.get("phone")).get_value(), request.get("phone_verification_code")
        )

    @classmethod
    def recover_password(cls, user, request: Request, **kwargs):
        return AuthentificationService.recover_password(request.get("login"))

    @classmethod
    def vk_auth(cls, user, request: Request, **kwargs):
        vkid = request.get("id")
        name = request.get("name")
        href = request.get("href")
        photo = request.get("photo")
        vk_data = request.get("vk_app_%d" % VK_APP_ID)
        vk_data, sig = vk_data.split("&sig=")
        target_user = AuthentificationService.authentificate_by_vk(user, vkid, name, href, photo, vk_data, sig)
        if target_user:
            request.response.set_cookie(
                "token", target_user.token,
                path="/", expires=datetime.now() + timedelta(days=30)
            )
            return {
                "redirect_to": cls.root,
                "user": target_user.data,
                "preview_randomizer": datetime.now().microsecond
            }