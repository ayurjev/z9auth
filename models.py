"""
    Models for
    Authentification service z9auth
"""

import os
import random
import hashlib
from datetime import datetime, timedelta
from exceptions import *
from typing import Optional, Tuple

from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError


def md5(value):
    """ Generates md5-hash for given string or bytes
    :param value: Value to be hashed
    :return: md5-hash
    """
    if not isinstance(value, bytes):
        value = str(value).encode()
    return hashlib.md5(value).hexdigest()


class Credentials(object):
    """ Model for convinient use of credentials """
    def __init__(self):
        self.email = None
        self.phone = None
        self.password = None
        self.token = None

    def set_email(self, email: str) -> None:
        """ Adds an email into Credentials object
        :param email: Email used as a login
        """
        self.email = email

    def set_phone(self, phone: str) -> None:
        """ Adds a phone into Credentisals object
        :param phone: Phone number used as a login
        """
        self.phone = phone

    def set_password(self, password: str) -> None:
        """ Adds a password into Credentials object
        :param password: Password for specified login (email or phone)
        :return:
        """
        self.password = password

    def set_token(self, token: str) -> None:
        """ Adds a token into Credentials object
        :param token: Authentification token (secret)
        """
        self.token = token


class AuthentificationService(object):
    """ Authentification service itself

        Does all work to confirm or deny authority of user by given credentials.
        Also, handles operations in order to create/remove credentials,
        set verification codes for email/phone or change existing password.
    """

    def __init__(self):
        self.client = MongoClient('mongo', 27017)
        self.credentials = self.client.db.credentials

    def get_credentials_record(self, credentials: Credentials) -> Optional[dict]:
        """ Returns a record from the storage if match found, otherwise None
        :param credentials: Credentials object
        :return: Dictionary of data stored in storage
        """
        match = None
        if credentials.token:
            match = self.credentials.find_one({"token": credentials.token})
        if credentials.email:
            match = self.credentials.find_one({"email": credentials.email})
        if credentials.phone:
            match = self.credentials.find_one({"phone": credentials.phone})
        return match

    def insert_inc(self, doc: dict) -> int:
        """

        :param doc:
        :return:
        """
        while True:
            cursor = self.credentials.find({}, {"_id": 1}).sort([("_id", DESCENDING)]).limit(1)
            try:
                doc["_id"] = next(cursor)["_id"] + 1
            except StopIteration:
                doc["_id"] = 1
            try:
                self.credentials.insert_one(doc)
                break
            except DuplicateKeyError:
                pass
        return doc["_id"]

    def register(self, credentials: Credentials) -> str:
        """ Initiates registration process: creates credentials record, generates verification code
        :param credentials: Credentials object
        :return: Verification code
        """
        match = self.get_credentials_record(credentials)
        if match:
            raise AlreadyRegistred()
        if not credentials.email and not credentials.phone:
            raise IncorrectLogin()
        if not credentials.password:
            raise IncorrectPassword()

        doc = {
            "email": None,
            "phone": None,
            "vk": None,
            "token": self.generate_new_token(),
            "password": md5(credentials.password),
            "email_tmp": credentials.email,
            "phone_tmp": credentials.phone,
            "email_verified": False,
            "phone_verified": False,
            "verification_code_failed_attempts": 0,
            "last_verification_attempt": None,
            "verification_code": self.gen_pincode()
        }
        self.insert_inc(doc)
        return doc["verification_code"]

    def authentificate(self, credentials: Credentials) -> Tuple[int, str]:
        """
        Does an authentification by given credentials
        @param credentials: Credentials object
        @raise IncorrectLogin:
        @raise IncorrectPassword:
        @return:
        """
        match = self.get_credentials_record(credentials)

        if not match:
            raise IncorrectLogin()
        elif match and (credentials.email or credentials.phone) and match["password"] != md5(credentials.password):
            raise IncorrectPassword()
        else:
            if credentials.email or credentials.phone:
                token = self.generate_new_token()
                self.credentials.update_one(match, {"$set": {"token": token}})
            else:
                token = match["token"]
            return match["_id"], token

    def recover_password(self, credentials: Credentials) -> str:
        """
        Changes password of the account
        @param credentials: Credentials object
        @return:
        """
        new_password = self.gen_password()
        match = self.get_credentials_record(credentials)
        if match and match["email"] and match["email_verified"]:
            self.credentials.update_one(match, {"$set": {"password": md5(new_password)}})
            return "email", new_password
        elif match and match["phone"] and match["phone_verified"]:
            self.credentials.update_one(match, {"$set": {"password": md5(new_password)}})
            return "phone", new_password
        else:
            raise IncorrectLogin()

    def set_new_password(self, credentials: Credentials, old_pass: str, new_pass: str, new_pass2: str) -> bool:
        """
        Меняет пароль аккаунта на новый
        @param credentials: Credentials object
        @param old_pass: Текущий пароль
        @param new_pass: Новый пароль
        @param new_pass2: Подтверждение нового пароля
        @return: Результат смены пароля
        """
        auth = self.authentificate(credentials)
        if auth:
            match = self.get_credentials_record(credentials)
            if match:
                if match["password"] != md5(old_pass):
                    raise IncorrectPassword()
                if new_pass != new_pass2:
                    raise NewPasswordsMismatch()

                if match and match["email"] and match["email_verified"]:
                    self.credentials.update_one(match, {"$set": {"password": md5(new_pass)}})
                    return "email", new_pass
                elif match and match["phone"] and match["phone_verified"]:
                    self.credentials.update_one(match, {"$set": {"password": md5(new_pass)}})
                    return "phone", new_pass

    def set_new_email(self, credentials: Credentials, new_email):
        auth = self.authentificate(credentials)
        if auth:
            match = self.get_credentials_record(credentials)
            if match:
                change = {
                    "email_tmp": new_email,
                    "verification_code_failed_attempts": 0,
                    "last_verification_attempt": None,
                    "verification_code": self.gen_pincode()
                }
                self.credentials.update_one(match, {"$set": change})
                return change["verification_code"]

    def set_new_phone(self, credentials: Credentials, new_phone):
        auth = self.authentificate(credentials)
        if auth:
            match = self.get_credentials_record(credentials)
            if match:
                change = {
                    "phone_tmp": new_phone,
                    "verification_code_failed_attempts": 0,
                    "last_verification_attempt": None,
                    "verification_code": self.gen_pincode()
                }
                self.credentials.update_one(match, {"$set": change})
                return change["verification_code"]

    @classmethod
    def gen_password(cls):
        """ Дефолтная реализация генерации пароля """
        digits = [1, 2, 3, 4, 5, 6, 7, 8, 9]
        characters = ["a", "b", "d", "e", "f", "g", "h", "j", "k", "m", "n",
                      "p", "q", "r", "s", "t", "u", "v", "w", "x", "y", "z" ]
        digit1 = str(random.choice(digits))
        digit2 = str(random.choice(digits))
        upper_char = random.choice(characters).upper()
        random.shuffle(characters)
        random_start = random.choice([1,2,3,4,5,6,7,8,9,10,11,12,13,14,15,16])
        random_end = random_start + 5
        chars = characters[random_start:random_end]
        l = [digit1, digit2, upper_char] + chars
        random.shuffle(l)
        return "".join(l)

    @classmethod
    def gen_pincode(cls):
        """ Дефолтная реализация генерации пин-кода """
        return "%d%d%d%d" % (
            random.choice(range(9)), random.choice(range(9)), random.choice(range(9)), random.choice(range(9))
        )

    @classmethod
    def generate_new_token(cls):
        """ Generates a new auth-token """
        return md5("%s%d" % (str(datetime.now()), random.choice(range(100))))

    def check_phone_registration(self, phone: str) -> bool:
        """ Метод проверки регистрации по номеру телефона
        :param phone: Номер телефона
        :return:
        """
        return self.credentials.find_one({"phone": phone, "phone_verified": True}) is not None

    def check_email_registration(self, email: str) -> bool:
        """ Метод проверки регистрации по адресу электронной почты
        :param email: Электронная почта
        :return:
        """
        return self.credentials.find_one({"email": email, "email_verified": True}) is not None

    def check_verification_code(self, target_user: dict, verification_code: str) -> bool:
        """ Проверяет код верификации
        :param target_user:
        :param verification_code:
        :return:
        """
        if not verification_code or verification_code != target_user["verification_code"]:
            if target_user["verification_code_failed_attempts"] < 3:
                self.credentials.update_one(target_user, {"$inc": {"verification_code_failed_attempts": 1}})
                raise IncorrectVerificationCode()
            else:
                if not target_user["email_verified"] and not target_user["phone_verified"]:
                    self.credentials.delete_one(target_user)
                else:
                    self.credentials.update_one(
                        target_user, {"$set": {
                            "verification_code": None, "last_verification_attempt": None,
                            "verification_code_failed_attempts": 0
                        }}
                    )
                raise IncorrectVerificationCodeFatal()
        return True

    def _verify(self, credentials: Credentials, verification_code: str, type_name: str):
        target_user = self.get_credentials_record(credentials)
        if target_user and (target_user["email_verified"] or target_user["phone_verified"]):
            self.authentificate(credentials)
            target_user = self.get_credentials_record(credentials) # because authentificate() changes token
        else:
            target_user = self.credentials.find_one({
                "%s_tmp" % type_name: object.__getattribute__(credentials, type_name)
            })
            if not target_user or target_user["email_verified"] or target_user["phone_verified"]:
                raise IncorrectLogin()

        if target_user["last_verification_attempt"] and \
                        target_user["last_verification_attempt"] < datetime.now() - timedelta(seconds=10*60):
            raise VerificationTimeExceeded()

        if self.check_verification_code(target_user, verification_code):
            self.credentials.update_one(
                target_user, {"$set": {
                    "%s" % type_name: target_user["%s_tmp" % type_name],
                    "%s_tmp" % type_name: None,
                    "%s_verified" % type_name: True,
                    "verification_code": None, "last_verification_attempt": None,
                    "verification_code_failed_attempts": 0
                }}
            )
            return True

    def verify_email(self, credentials: Credentials, verification_code: str):
        """ Подтверждает регистрационный данные (email) на основе кода верификации
        @param credentials:
        @param verification_code:
        """
        return self._verify(credentials, verification_code, "email")

    def verify_phone(self, credentials: Credentials, verification_code: str) -> bool:
        """ Подтверждает номер телефона
        @param credentials:
        @param verification_code:
        """
        return self._verify(credentials, verification_code, "phone")

    @classmethod
    def authentificate_by_vk(cls, login, vkid, name, href, photo, vk_data, sig):
        """ Выполняет аутентификацию на основе Вконтакте API
        :param login: Логин пользователя
        :param vkid: Идентификатор Вк
        :param name: Имя пользователя согласно Вк
        :param href: URL пользователя Вк
        :param photo: Аватарка пользователя Вк
        :param vk_data: Данные Вк для проверки подписи
        :param sig: Подпись
        :return:
        """
        if not md5(vk_data.replace("&", "") + os.environ.get("VK_APP_SECRET_KEY")) == sig:
            raise IncorrectOAuthSignature()

        user_by_vkid = object
        user_by_login = object

        if user_by_login and not user_by_vkid:
            target_user = user_by_login
        elif user_by_vkid and not user_by_login:
            target_user = user_by_vkid
        elif user_by_vkid and user_by_login:
            target_user = user_by_vkid
        else:
            target_user = object
            target_user.password = cls.gen_password()
            target_user.token = md5(cls.gen_password())

        target_user.name = name
        target_user.vk = vkid
        target_user.vk_href = href
        return True