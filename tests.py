
""" Тесты """

import os
import unittest
from exceptions import *
from models import AuthenticationService, Credentials, md5


class RegistrationCase(unittest.TestCase):

    def setUp(self):
        self.service = AuthenticationService()

    def tearDown(self):
        self.service.credentials.delete_many({})

    def test_init_registration_process_with_email(self):
        credentials = Credentials()
        self.assertRaises(IncorrectLogin, lambda: self.service.register(credentials))
        credentials.email = "andrey.yurjev@test.ru"
        self.assertRaises(IncorrectPassword, lambda: self.service.register(credentials))
        credentials.password = "qwerty123"
        verification_code = self.service.register(credentials)
        self.assertTrue(isinstance(verification_code, str))
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(credentials))
        self.assertTrue(self.service.verify_email(credentials, verification_code))

        auth_result = self.service.authenticate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_init_registration_process_with_phone(self):
        credentials = Credentials()
        credentials.phone = "+79263435016"
        credentials.password = "qwerty123"
        verification_code = self.service.register(credentials)
        self.assertTrue(isinstance(verification_code, str))
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(credentials))
        self.assertTrue(self.service.verify_phone(credentials, verification_code))

        auth_result = self.service.authenticate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_fail_email_verification_and_delete_account(self):
        credentials = Credentials()
        credentials.email = "andrey.yurjev@test.ru"
        credentials.password = "qwerty123"
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCodeFatal, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_email(credentials, verification_code))

    def test_fail_phone_verification_and_delete_account(self):
        credentials = Credentials()
        credentials.phone = "+79263435016"
        credentials.password = "qwerty123"
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCodeFatal, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_phone(credentials, verification_code))

    def test_email_verification_with_third_attempt(self):
        credentials = Credentials()
        credentials.email = "andrey.yurjev@test.ru"
        credentials.password = "qwerty123"
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertTrue(self.service.verify_email(credentials, verification_code))

        auth_result = self.service.authenticate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_phone_verification_with_third_attempt(self):
        credentials = Credentials()
        credentials.phone = "+79263435016"
        credentials.password = "qwerty123"
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertTrue(self.service.verify_phone(credentials, verification_code))

        auth_result = self.service.authenticate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))


class AuthentificationCase(unittest.TestCase):

    def setUp(self):
        self.service = AuthenticationService()
        self.email_credentials = Credentials()
        self.email_credentials.email = "andrey.yurjev@test.ru"
        self.email_credentials.password = "qwerty123"
        verification_code = self.service.register(self.email_credentials)
        self.service.verify_email(self.email_credentials, verification_code)

        self.phone_credentials = Credentials()
        self.phone_credentials.phone = "+79263435016"
        self.phone_credentials.password = "qwerty123"
        verification_code = self.service.register(self.phone_credentials)
        self.service.verify_phone(self.phone_credentials, verification_code)

    def tearDown(self):
        self.service.credentials.delete_many({})

    def test_successfull_auth_with_login_and_password(self):
        auth_result = self.service.authenticate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        auth_result = self.service.authenticate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_wrong_login_and_then_success(self):
        self.email_credentials.email = "bla@bla.ru"
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(self.email_credentials))
        self.email_credentials.email = "andrey.yurjev@test.ru"
        auth_result = self.service.authenticate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        self.phone_credentials.phone = "911"
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(self.phone_credentials))
        self.phone_credentials.phone = "+79263435016"
        auth_result = self.service.authenticate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_wrong_password_and_then_success(self):
        self.email_credentials.password = "secret"
        self.assertRaises(IncorrectPassword, lambda: self.service.authenticate(self.email_credentials))
        self.email_credentials.password = "qwerty123"
        auth_result = self.service.authenticate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        self.phone_credentials.password = "secret"
        self.assertRaises(IncorrectPassword, lambda: self.service.authenticate(self.phone_credentials))
        self.phone_credentials.password = "qwerty123"
        auth_result = self.service.authenticate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_password_recovery(self):
        self.email_credentials.password = "secret"
        self.assertRaises(IncorrectPassword, lambda: self.service.authenticate(self.email_credentials))
        recover_result = self.service.recover_password(self.email_credentials)
        self.assertTrue(isinstance(recover_result, tuple))
        self.assertEqual("email", recover_result[0])
        self.assertTrue(isinstance(recover_result[1], str))

        self.email_credentials.password = recover_result[1]
        auth_result = self.service.authenticate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        self.phone_credentials.password = "secret"
        self.assertRaises(IncorrectPassword, lambda: self.service.authenticate(self.phone_credentials))
        recover_result = self.service.recover_password(self.phone_credentials)
        self.assertTrue(isinstance(recover_result, tuple))
        self.assertEqual("phone", recover_result[0])
        self.assertTrue(isinstance(recover_result[1], str))

        self.phone_credentials.password = recover_result[1]
        auth_result = self.service.authenticate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_auth_by_token(self):
        auth_result = self.service.authenticate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))
        token = auth_result[1]

        new_credentials = Credentials()
        new_credentials.token = token
        auth_result = self.service.authenticate(new_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(token, token)
        # При авторизации по токену, токен не меняется:
        auth_result = self.service.authenticate(new_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(token, token)


class ChangeCredentialsCase(unittest.TestCase):

    def setUp(self):
        self.service = AuthenticationService()
        self.email_credentials = Credentials()
        self.email_credentials.email = "andrey.yurjev@test.ru"
        self.email_credentials.password = "qwerty123"
        verification_code = self.service.register(self.email_credentials)
        self.service.verify_email(self.email_credentials, verification_code)
        auth_result = self.service.authenticate(self.email_credentials)
        self.email_account_token = auth_result[1]

        self.phone_credentials = Credentials()
        self.phone_credentials.phone = "+79263435016"
        self.phone_credentials.password = "qwerty123"
        verification_code = self.service.register(self.phone_credentials)
        self.service.verify_phone(self.phone_credentials, verification_code)
        auth_result = self.service.authenticate(self.phone_credentials)
        self.phone_account_token = auth_result[1]

    def tearDown(self):
        self.service.credentials.delete_many({})

    def test_change_password(self):
        credentials = Credentials()
        credentials.token = self.email_account_token
        self.assertRaises(IncorrectPassword, self.service.set_new_password, credentials, "blabla", "123", "456")
        self.assertRaises(NewPasswordsMismatch, self.service.set_new_password, credentials, "qwerty123", "123", "456")
        change_password_result = self.service.set_new_password(credentials, "qwerty123", "12345", "12345")
        self.assertTrue(isinstance(change_password_result, tuple))
        self.assertEqual("email", change_password_result[0])
        self.assertEqual("12345", change_password_result[1])

        credentials = Credentials()
        credentials.token = self.phone_account_token
        self.assertRaises(IncorrectPassword, self.service.set_new_password, credentials, "blabla", "123", "456")
        self.assertRaises(NewPasswordsMismatch, self.service.set_new_password, credentials, "qwerty123", "123", "456")
        change_password_result = self.service.set_new_password(credentials, "qwerty123", "12345", "12345")
        self.assertTrue(isinstance(change_password_result, tuple))
        self.assertEqual("phone", change_password_result[0])
        self.assertEqual("12345", change_password_result[1])

    def test_set_and_verify_phone_when_email_verified(self):
        verification_code = self.service.set_new_phone(self.email_credentials, "+79164143212")
        new_phone_credentials = Credentials()
        new_phone_credentials.phone = "+79164143212"
        new_phone_credentials.password = self.email_credentials.password
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(new_phone_credentials))
        self.service.authenticate(self.email_credentials)
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_phone(new_phone_credentials, verification_code))
        self.service.verify_phone(self.email_credentials, verification_code)
        self.service.authenticate(new_phone_credentials)
        self.service.authenticate(self.email_credentials)

    def test_set_and_verify_new_email_when_email_verified(self):
        verification_code = self.service.set_new_email(self.email_credentials, "newemail@newemail.com")
        new_email_credentials = Credentials()
        new_email_credentials.email = "newemail@newemail.com"
        new_email_credentials.password = self.email_credentials.password
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(new_email_credentials))
        self.service.authenticate(self.email_credentials)
        self.service.verify_email(self.email_credentials, verification_code)
        self.service.authenticate(new_email_credentials)
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(self.email_credentials))

    def test_set_and_verify_email_when_phone_verified(self):
        verification_code = self.service.set_new_email(self.phone_credentials, "newemail@newemail.com")
        new_email_credentials = Credentials()
        new_email_credentials.email = "newemail@newemail.com"
        new_email_credentials.password = self.phone_credentials.password
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(new_email_credentials))
        self.service.authenticate(self.phone_credentials)
        self.service.verify_email(self.phone_credentials, verification_code)
        self.service.authenticate(new_email_credentials)
        self.service.authenticate(self.phone_credentials)

    def test_set_and_verify_new_phone_when_phone_verified(self):
        verification_code = self.service.set_new_phone(self.phone_credentials, "+79212225577")
        new_phone_credentials = Credentials()
        new_phone_credentials.phone = "+79212225577"
        new_phone_credentials.password = self.phone_credentials.password
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(new_phone_credentials))
        self.service.authenticate(self.phone_credentials)
        self.service.verify_phone(self.phone_credentials, verification_code)
        self.service.authenticate(new_phone_credentials)
        self.assertRaises(IncorrectLogin, lambda: self.service.authenticate(self.phone_credentials))


class VkAuthCase(unittest.TestCase):

    def setUp(self):
        self.service = AuthenticationService()

    def tearDown(self):
        self.service.credentials.delete_many({})

    def test_init_registration_with_vk(self):
        os.environ["VK_APP_SECRET_KEY"] = "12345"
        vk_id = 42
        vk_concated_string = "blablabla=1&blabla=2"
        sig = md5(vk_concated_string.replace("&", "") + "12345")
        credentials = Credentials()
        credentials.vk_id = vk_id
        result = self.service.authenticate_vk(credentials, vk_concated_string, sig)
        self.assertTrue(isinstance(result, tuple))
        self.assertEqual(1, result[0])
        self.assertEqual(32, len(result[1]))
        token = result[1]

        # Используя токен, полученный при регистрации через вк авторизуемся стандартным путем:
        credentials.token = token
        auth_result = self.service.authenticate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(token, auth_result[1])

    def test_vk_auth_after_normal_registartion(self):
        os.environ["VK_APP_SECRET_KEY"] = "12345"
        vk_id = 42
        vk_concated_string = "blablabla=1&blabla=2"
        sig = md5(vk_concated_string.replace("&", "") + "12345")

        # Обычная регистрация, получаем токен:
        credentials = Credentials()
        credentials.phone = "+79263435016"
        credentials.password = "qwerty123"
        verification_code = self.service.register(credentials)
        self.service.verify_phone(credentials, verification_code)
        auth_result = self.service.authenticate(credentials)
        self.assertEqual(1, auth_result[0])
        token = auth_result[1]

        # Используем токен и укажем vk_id:
        new_credentials = Credentials()
        new_credentials.token = token
        new_credentials.vk_id = vk_id
        vk_auth_result = self.service.authenticate_vk(new_credentials, vk_concated_string, sig)
        self.assertTrue(isinstance(vk_auth_result, tuple))
        self.assertEqual(1, vk_auth_result[0])
        self.assertEqual(token, vk_auth_result[1])

        # Теперь можно и без токена:
        new_credentials = Credentials()
        new_credentials.vk_id = vk_id
        vk_auth_result = self.service.authenticate_vk(new_credentials, vk_concated_string, sig)
        self.assertTrue(isinstance(vk_auth_result, tuple))
        self.assertEqual(1, vk_auth_result[0])
        self.assertEqual(32, len(vk_auth_result[1]))
        self.assertNotEqual(token, vk_auth_result[1])

    def test_vk_auth_fail(self):
        os.environ["VK_APP_SECRET_KEY"] = "12345"
        vk_id = 42
        vk_concated_string = "blablabla=1&blabla=2"
        sig = md5(vk_concated_string.replace("&", "") + "12345")
        credentials = Credentials()
        credentials.vk_id = vk_id
        self.assertRaises(
            IncorrectOAuthSignature,
            self.service.authenticate_vk, credentials, vk_concated_string, sig+"1"
        )