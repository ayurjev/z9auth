""" Модели """

import os
import re
import random
import hashlib
from datetime import datetime, timedelta
from exceptions import *
from typing import Optional, Tuple, Union

from pymongo import MongoClient, DESCENDING
from pymongo.errors import DuplicateKeyError


class AuthenticationService(object):
    """ Модель сервиса аутентификации """

    def __init__(self):
        self.client = MongoClient('mongo', 27017, connect=False)
        self.credentials = self.client.db.credentials

    def get_credentials(self, uid: int):
        """ Возвращает учетные данные по id
        :param uid:
        :return:
        """
        match = self.credentials.find_one({"_id": uid})
        if not match:
            raise NoSuchUser()
        return {
            "email": match.get("email"),
            "email_tmp": match.get("email_tmp"),
            "email_verified": match.get("email_verified"),
            "phone": match.get("phone"),
            "phone_tmp": match.get("phone_tmp"),
            "phone_verified": match.get("phone_verified"),
            "vk_id": match.get("vk_id")
        }

    def register(self, credentials: 'Credentials', email_verified: bool=False, phone_verified: bool=False) -> str:
        """ Начинает процедуру регистрации, создает пустую запись, генерирует и возвращает код верификации
        :param credentials:
        :param email_verified:
        :param phone_verified:
        :return:
        """
        match = self._get_credentials_record(credentials)
        if match:
            raise AlreadyRegistred()

        if not credentials.email and not credentials.phone and not credentials.vk_id:
            raise IncorrectLogin()
        if (credentials.email or credentials.phone) and not credentials.password:
            credentials.password = CodesGenerator.gen_password()

        new_code = CodesGenerator.gen_pincode()

        interrupted_registration_attempt_match = self.credentials.find_one(
            {"email_tmp": credentials.email, "email_verified": False, "phone_verified": False} if credentials.email else
            {"phone_tmp": credentials.phone, "email_verified": False, "phone_verified": False}
        )
        if interrupted_registration_attempt_match:
            self.credentials.update_one(
                {"_id": interrupted_registration_attempt_match["_id"]},
                {"$set": {
                    "verification_code": new_code,
                    "password": credentials.password
                }}
            )
            uid = interrupted_registration_attempt_match["_id"]
        else:
            doc = {
                "email": credentials.email if email_verified else None,
                "phone": credentials.phone if phone_verified else None,
                "vk_id": credentials.vk_id,
                "%stoken" % credentials.token_name: CodesGenerator.gen_token(),
                "password": credentials.password,
                "email_tmp": credentials.email,
                "phone_tmp": credentials.phone,
                "email_verified": email_verified,
                "phone_verified": phone_verified,
                "verification_code_failed_attempts": 0,
                "last_verification_attempt": None,
                "verification_code": new_code
            }
            uid = self._insert_inc(doc)
        return {
            "verification": {
                "id": uid,
                "password": credentials.password,
                "send_code": new_code,
                "send_via": "email" if credentials.email else ("phone" if credentials.phone else None),
                "send_address": credentials.email or credentials.phone
            }
        }

    def authenticate(self, credentials: 'Credentials') -> Tuple[int, str]:
        """ Выполняет попытку аутентификации пользователя на основе предоставленных данных
        @param credentials:
        @return:
        """
        match = self._get_credentials_record(credentials)
        if not match:
            raise IncorrectLogin()
        elif match and (credentials.email or credentials.phone) and match["password"] != md5(credentials.password):
            raise IncorrectPassword()
        else:
            if credentials.email or credentials.phone:
                token = CodesGenerator.gen_token()
                self.credentials.update_one(match, {"$set": {"%stoken" % credentials.token_name: token}})
            else:
                token = match["%stoken" % credentials.token_name]
            return {"authentication": {"id": match["_id"], "%stoken" % credentials.token_name: token}}

    def authenticate_vk(self, credentials: 'Credentials', code: str, redirect_url: str=None):
        """ Выполняет аутентификацию на основе Вконтакте API
        :param credentials:
        :param code: Код аутентификации ВК
        :param redirect_url: Дополнительная часть URL редиректа (опционально)
        :return:
        """
        import json
        import requests
        data = {
            "client_id": os.environ.get("VK_APP_ID"),
            "client_secret": os.environ.get("VK_APP_SECRET_KEY"),
            "redirect_uri": "%s%s" % (os.environ.get("VK_REDIRECT_URI"), redirect_url if redirect_url else ""),
            "code": code
        }

        vk_id = None
        # noinspection PyBroadException
        try:
            r = requests.post("https://oauth.vk.com/access_token", data)
            result = json.loads(r.text)
            print(result)
            vk_id = result.get("user_id")
            if not vk_id:
                raise IncorrectOAuthSignature()
            data2 = {
                "user_ids": result.get("user_id"),
                "v": "5.8",
                "access_token": result.get("access_token"),
                "fields": os.environ.get("VK_SCOPE", "photo_max,contacts,interests,music,sex,city,bdate")
            }
            r2 = requests.post("https://api.vk.com/method/users.get", data2)
            result2 = json.loads(r2.text)
            result2 = result2.get("response")[0] if result2.get("response") else {}
            result2["vk_id"] = result.get("user_id")
            result2["email"] = result.get("email")
            result2["phone"] = result2.get("mobile_phone", result2.get("home_phone", None))
            if result2.get("phone"):
                result2["phone"] = normalize_phone_number(result2["phone"])
            print(result2)
        except Exception as err:
            print(err)
            raise IncorrectOAuthSignature()

        if result and result.get("error"):
            print(result)
            raise IncorrectOAuthSignature()

        if not vk_id:
            raise IncorrectOAuthSignature()

        credentials.vk_id = int(vk_id)
        credentials.email = result2.get("email")
        credentials.phone = result2.get("phone")

        match = self._get_credentials_record(credentials)
        if match:
            token = CodesGenerator.gen_token()
            self.credentials.update_one(
                match, {
                    "$set": {
                        "vk_id": credentials.vk_id,
                        "%stoken" % credentials.token_name: token,
                        "phone": result2.get("phone") if result2.get("phone") else (match["phone"] if match["phone_verified"] else None),
                        "email": result2.get("email") if result2.get("email") else (match["email"] if match["email_verified"] else None),
                        "email_verified": True if result2.get("email") else match["email_verified"],
                        "phone_verified": True if result2.get("phone") else match["phone_verified"]
                    }
                }
            )
        else:
            self.register(credentials, email_verified=True, phone_verified=True)
            match = self._get_credentials_record(credentials)
            token = match["%stoken" % credentials.token_name]
        return {"authentication": {"id": match["_id"], "%stoken" % credentials.token_name: token, "vk_data": result2}}

    def recover_password(self, credentials: 'Credentials') -> str:
        """ Меняет пароль пользователя на новый и возвращает его с указанием по какому каналу его можно выслать
        @param credentials:
        @return:
        """
        new_password = CodesGenerator.gen_password()
        match = self._get_credentials_record(credentials)
        if match and match["email"] and match["email_verified"]:
            self.credentials.update_one(match, {"$set": {"password": md5(new_password)}})
            return {"password_recovery": {
                "send_password": new_password, "send_via": "email", "send_address": credentials.email
            }}
        elif match and match["phone"] and match["phone_verified"]:
            self.credentials.update_one(match, {"$set": {"password": md5(new_password)}})
            return {"password_recovery": {
                "send_password": new_password, "send_via": "phone", "send_address": credentials.phone
            }}
        else:
            raise IncorrectLogin()

    def set_new_password(self, credentials: 'Credentials', old_pass: str, new_pass: str, new_pass2: str) -> bool:
        """ Меняет пароль аккаунта на новый (При смене после авторизации, из профиля) и
        возвращает его с указанием канала, по которому пользователю можно сообщить о смене
        @param credentials:
        @param old_pass: Текущий пароль
        @param new_pass: Новый пароль
        @param new_pass2: Подтверждение нового пароля
        @return:
        """
        auth = self.authenticate(credentials)
        if auth:
            match = self._get_credentials_record(credentials)
            if match:
                if match["password"] != md5(old_pass):
                    raise IncorrectPassword()
                if new_pass != new_pass2:
                    raise NewPasswordsMismatch()

                if match and match["email"] and match["email_verified"]:
                    self.credentials.update_one(match, {"$set": {"password": md5(new_pass)}})
                    return {"new_password": {
                        "send_password": new_pass, "send_via": "email", "send_address": match["email"]
                    }}
                elif match and match["phone"] and match["phone_verified"]:
                    self.credentials.update_one(match, {"$set": {"password": md5(new_pass)}})
                    return {"new_password": {
                        "send_password": new_pass, "send_via": "phone", "send_address": match["phone"]
                    }}

    def set_new_email(self, credentials: 'Credentials', new_email: str) -> str:
        """ Начинает процесс смены email адреса, ставит его в tmp-состояние и возвращает код верификации
        :param credentials:
        :param new_email:
        :return:
        """
        auth = self.authenticate(credentials)
        if auth:
            match = self._get_credentials_record(credentials)
            if match:
                change = {
                    "email_tmp": new_email,
                    "verification_code_failed_attempts": 0,
                    "last_verification_attempt": None,
                    "verification_code": CodesGenerator.gen_pincode()
                }
                self.credentials.update_one(match, {"$set": change})
                return {"verification": {
                    "send_code": change["verification_code"], "send_via": "email", "send_address": new_email
                }}

    def set_new_phone(self, credentials: 'Credentials', new_phone: str) -> str:
        """ Начинает процесс смены номера телефона, ставит его в tmp-состояние и возвращает код верификации
        :param credentials:
        :param new_phone:
        :return:
        """
        auth = self.authenticate(credentials)
        if auth:
            match = self._get_credentials_record(credentials)
            if match:
                change = {
                    "phone_tmp": new_phone,
                    "verification_code_failed_attempts": 0,
                    "last_verification_attempt": None,
                    "verification_code": CodesGenerator.gen_pincode()
                }
                self.credentials.update_one(match, {"$set": change})
                return {"verification": {
                    "send_code": change["verification_code"], "send_via": "phone", "send_address": new_phone
                }}

    def verify_email(self, credentials: 'Credentials', verification_code: str) -> bool:
        """ Подтверждает регистрационный данные (email) на основе кода верификации
        @param credentials:
        @param verification_code:
        """
        return self._verify(credentials, verification_code, "email")

    def verify_phone(self, credentials: 'Credentials', verification_code: str) -> bool:
        """ Подтверждает номер телефона
        @param credentials:
        @param verification_code:
        """
        return self._verify(credentials, verification_code, "phone")

    def get_account_if_exists(self, credentials: 'Credentials') -> Optional[dict]:
        """ Возвращает идентификатор пользовтеля, если он найден
        :param credentials:
        :return:
        """
        match = self._get_credentials_record(credentials)
        return {"id": match["_id"]} if match else None

    def _get_credentials_record(self, credentials: 'Credentials') -> Optional[dict]:
        """ Возвращает запись из БД, соответствующую переданным учетным данным, если такие найдены
        :param credentials:
        :return:
        """
        match = None
        if credentials.vk_id:
            match = self.credentials.find_one({"vk_id": credentials.vk_id})
        if not match and credentials.token:
            match = self.credentials.find_one({"%stoken" % credentials.token_name: credentials.token})
        if not match and credentials.email:
            match = self.credentials.find_one({"email": credentials.email})
        if not match and credentials.phone:
            match = self.credentials.find_one({"phone": credentials.phone})
        return match

    def _check_verification_code(self, target_user: dict, verification_code: str) -> bool:
        """ Проверяет код верификации
        :param target_user:
        :param verification_code:
        :return:
        """
        if not target_user["verification_code"]:
            raise NoVerificationProcess()

        if not verification_code or int(verification_code) != int(target_user["verification_code"]):
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

    def _verify(self, credentials: 'Credentials', verification_code: str, type_name: str) -> bool:
        """ Верифицирует либо email либо phone в зависимости от type_name
        :param credentials:
        :param verification_code:
        :param type_name:
        :return:
        """
        target_user = self._get_credentials_record(credentials)
        if target_user and (target_user["email_verified"] or target_user["phone_verified"]):
            self.authenticate(credentials)
            target_user = self._get_credentials_record(credentials) # because authenticate() changes token
        else:
            target_user = self.credentials.find_one({
                "%s_tmp" % type_name: object.__getattribute__(credentials, type_name)
            })
            if not target_user or target_user["email_verified"] or target_user["phone_verified"]:
                raise IncorrectLogin()

        if target_user["last_verification_attempt"] and \
                        target_user["last_verification_attempt"] < datetime.now() - timedelta(seconds=10*60):
            raise VerificationTimeExceeded()

        if self._check_verification_code(target_user, verification_code):
            self.credentials.update_one(
                target_user, {"$set": {
                    "password": md5(target_user["password"])
                    if not target_user["email_verified"] and not target_user["phone_verified"]
                    else target_user["password"],
                    "%s" % type_name: target_user["%s_tmp" % type_name],
                    "%s_tmp" % type_name: None,
                    "%s_verified" % type_name: True,
                    "verification_code": None, "last_verification_attempt": None,
                    "verification_code_failed_attempts": 0
                }}
            )
            return {"verification": {"result": True, "password": target_user["password"]}}

    def _insert_inc(self, doc: dict) -> int:
        """ Вставляет новый документ в коллекцию учетных данных, генерируя инкрементный ключ - привет mongodb...
        :param doc: Документ для вставки в коллекцию (без указания _id)
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


class Credentials(object):
    """ Модель для хранения учетных данных """
    def __init__(self):
        self.email = None
        self.phone = None
        self.password = None
        self.token = None
        self.vk_id = None
        self.token_name = ""

    def __str__(self):
        return "%s  %s  %s  %s %s %s" % (self.email, self.phone, self.token_name, self.token, self.vk_id, self.password)


class CodesGenerator(object):
    """ Класс для генерации паролей, пин-кодов и токенов """
    @classmethod
    def gen_password(cls) -> str:
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
    def gen_pincode(cls) -> str:
        """ Дефолтная реализация генерации пин-кода """
        return "%d%d%d%d" % (
            random.choice(range(9)), random.choice(range(9)),
            random.choice(range(9)), random.choice(range(9))
        )

    @classmethod
    def gen_token(cls) -> str:
        """ Дефолтная реализации генерации токена """
        return md5("%s%d" % (str(datetime.now()), random.choice(range(100))))


def normalize_phone_number(number: str) -> str:
    """ Приводит номер к правильному строковому представлению
    :param number: Номер телефона
    """
    digits = re.sub("[^\d]", "", str(number))
    if len(digits) < 10:
        raise InvalidPhoneNumber(number)
    return "+7%s" % (digits[1 if digits[0] in ["7", "8"] else 0:11])


def md5(value: Union[str, bytes]) -> str:
    """ MD5
    :param value:
    :return: md5-хеш
    """
    if not isinstance(value, bytes):
        value = str(value).encode()
    return hashlib.md5(value).hexdigest()