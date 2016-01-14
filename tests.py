

import unittest
from models import AuthenticationService, Credentials
from exceptions import *


class RegistrationCase(unittest.TestCase):

    def setUp(self):
        self.service = AuthenticationService()

    def tearDown(self):
        self.service.credentials.delete_many({})

    def test_init_registration_process_with_email(self):
        credentials = Credentials()
        self.assertRaises(IncorrectLogin, lambda: self.service.register(credentials))
        credentials.set_email("andrey.yurjev@test.ru")
        self.assertRaises(IncorrectPassword, lambda: self.service.register(credentials))
        credentials.set_password("qwerty123")
        verification_code = self.service.register(credentials)
        self.assertTrue(isinstance(verification_code, str))
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(credentials))
        self.assertTrue(self.service.verify_email(credentials, verification_code))

        auth_result = self.service.authentificate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_init_registration_process_with_phone(self):
        credentials = Credentials()
        credentials.set_phone("+79263435016")
        credentials.set_password("qwerty123")
        verification_code = self.service.register(credentials)
        self.assertTrue(isinstance(verification_code, str))
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(credentials))
        self.assertTrue(self.service.verify_phone(credentials, verification_code))

        auth_result = self.service.authentificate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_fail_email_verification_and_delete_account(self):
        credentials = Credentials()
        credentials.set_email("andrey.yurjev@test.ru")
        credentials.set_password("qwerty123")
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCodeFatal, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_email(credentials, verification_code))

    def test_fail_phone_verification_and_delete_account(self):
        credentials = Credentials()
        credentials.set_phone("+79263435016")
        credentials.set_password("qwerty123")
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCodeFatal, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_phone(credentials, verification_code))

    def test_email_verification_with_third_attempt(self):
        credentials = Credentials()
        credentials.set_email("andrey.yurjev@test.ru")
        credentials.set_password("qwerty123")
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_email(credentials, "blablabla"))
        self.assertTrue(self.service.verify_email(credentials, verification_code))

        auth_result = self.service.authentificate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_phone_verification_with_third_attempt(self):
        credentials = Credentials()
        credentials.set_phone("+79263435016")
        credentials.set_password("qwerty123")
        verification_code = self.service.register(credentials)
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertRaises(IncorrectVerificationCode, lambda: self.service.verify_phone(credentials, "blablabla"))
        self.assertTrue(self.service.verify_phone(credentials, verification_code))

        auth_result = self.service.authentificate(credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))


class AuthentificationCase(unittest.TestCase):

    def setUp(self):
        self.service = AuthenticationService()
        self.email_credentials = Credentials()
        self.email_credentials.set_email("andrey.yurjev@test.ru")
        self.email_credentials.set_password("qwerty123")
        verification_code = self.service.register(self.email_credentials)
        self.service.verify_email(self.email_credentials, verification_code)

        self.phone_credentials = Credentials()
        self.phone_credentials.set_phone("+79263435016")
        self.phone_credentials.set_password("qwerty123")
        verification_code = self.service.register(self.phone_credentials)
        self.service.verify_phone(self.phone_credentials, verification_code)

    def tearDown(self):
        self.service.credentials.delete_many({})

    def test_successfull_auth_with_login_and_password(self):
        auth_result = self.service.authentificate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        auth_result = self.service.authentificate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_wrong_login_and_then_success(self):
        self.email_credentials.set_email("bla@bla.ru")
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(self.email_credentials))
        self.email_credentials.set_email("andrey.yurjev@test.ru")
        auth_result = self.service.authentificate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        self.phone_credentials.set_phone("911")
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(self.phone_credentials))
        self.phone_credentials.set_phone("+79263435016")
        auth_result = self.service.authentificate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_wrong_password_and_then_success(self):
        self.email_credentials.set_password("secret")
        self.assertRaises(IncorrectPassword, lambda: self.service.authentificate(self.email_credentials))
        self.email_credentials.set_password("qwerty123")
        auth_result = self.service.authentificate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        self.phone_credentials.set_password("secret")
        self.assertRaises(IncorrectPassword, lambda: self.service.authentificate(self.phone_credentials))
        self.phone_credentials.set_password("qwerty123")
        auth_result = self.service.authentificate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_password_recovery(self):
        self.email_credentials.set_password("secret")
        self.assertRaises(IncorrectPassword, lambda: self.service.authentificate(self.email_credentials))
        recover_result = self.service.recover_password(self.email_credentials)
        self.assertTrue(isinstance(recover_result, tuple))
        self.assertEqual("email", recover_result[0])
        self.assertTrue(isinstance(recover_result[1], str))

        self.email_credentials.set_password(recover_result[1])
        auth_result = self.service.authentificate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

        self.phone_credentials.set_password("secret")
        self.assertRaises(IncorrectPassword, lambda: self.service.authentificate(self.phone_credentials))
        recover_result = self.service.recover_password(self.phone_credentials)
        self.assertTrue(isinstance(recover_result, tuple))
        self.assertEqual("phone", recover_result[0])
        self.assertTrue(isinstance(recover_result[1], str))

        self.phone_credentials.set_password(recover_result[1])
        auth_result = self.service.authentificate(self.phone_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(2, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))

    def test_auth_by_token(self):
        auth_result = self.service.authentificate(self.email_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(32, len(auth_result[1]))
        token = auth_result[1]

        new_credentials = Credentials()
        new_credentials.set_token(token)
        auth_result = self.service.authentificate(new_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(token, token)
        # При авторизации по токену, токен не меняется:
        auth_result = self.service.authentificate(new_credentials)
        self.assertTrue(isinstance(auth_result, tuple))
        self.assertEqual(1, auth_result[0])
        self.assertEqual(token, token)


class ChangeCredentialsCase(unittest.TestCase):

    def setUp(self):
        self.service = AuthenticationService()
        self.email_credentials = Credentials()
        self.email_credentials.set_email("andrey.yurjev@test.ru")
        self.email_credentials.set_password("qwerty123")
        verification_code = self.service.register(self.email_credentials)
        self.service.verify_email(self.email_credentials, verification_code)
        auth_result = self.service.authentificate(self.email_credentials)
        self.email_account_token = auth_result[1]

        self.phone_credentials = Credentials()
        self.phone_credentials.set_phone("+79263435016")
        self.phone_credentials.set_password("qwerty123")
        verification_code = self.service.register(self.phone_credentials)
        self.service.verify_phone(self.phone_credentials, verification_code)
        auth_result = self.service.authentificate(self.phone_credentials)
        self.phone_account_token = auth_result[1]

    def tearDown(self):
        self.service.credentials.delete_many({})

    def test_change_password(self):
        credentials = Credentials()
        credentials.set_token(self.email_account_token)
        self.assertRaises(IncorrectPassword, self.service.set_new_password, credentials, "blabla", "123", "456")
        self.assertRaises(NewPasswordsMismatch, self.service.set_new_password, credentials, "qwerty123", "123", "456")
        change_password_result = self.service.set_new_password(credentials, "qwerty123", "12345", "12345")
        self.assertTrue(isinstance(change_password_result, tuple))
        self.assertEqual("email", change_password_result[0])
        self.assertEqual("12345", change_password_result[1])

        credentials = Credentials()
        credentials.set_token(self.phone_account_token)
        self.assertRaises(IncorrectPassword, self.service.set_new_password, credentials, "blabla", "123", "456")
        self.assertRaises(NewPasswordsMismatch, self.service.set_new_password, credentials, "qwerty123", "123", "456")
        change_password_result = self.service.set_new_password(credentials, "qwerty123", "12345", "12345")
        self.assertTrue(isinstance(change_password_result, tuple))
        self.assertEqual("phone", change_password_result[0])
        self.assertEqual("12345", change_password_result[1])

    def test_set_and_verify_phone_when_email_verified(self):
        verification_code = self.service.set_new_phone(self.email_credentials, "+79164143212")
        new_phone_credentials = Credentials()
        new_phone_credentials.set_phone("+79164143212")
        new_phone_credentials.set_password(self.email_credentials.password)
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(new_phone_credentials))
        self.service.authentificate(self.email_credentials)
        self.assertRaises(IncorrectLogin, lambda: self.service.verify_phone(new_phone_credentials, verification_code))
        self.service.verify_phone(self.email_credentials, verification_code)
        self.service.authentificate(new_phone_credentials)
        self.service.authentificate(self.email_credentials)

    def test_set_and_verify_new_email_when_email_verified(self):
        verification_code = self.service.set_new_email(self.email_credentials, "newemail@newemail.com")
        new_email_credentials = Credentials()
        new_email_credentials.set_email("newemail@newemail.com")
        new_email_credentials.set_password(self.email_credentials.password)
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(new_email_credentials))
        self.service.authentificate(self.email_credentials)
        self.service.verify_email(self.email_credentials, verification_code)
        self.service.authentificate(new_email_credentials)
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(self.email_credentials))

    def test_set_and_verify_email_when_phone_verified(self):
        verification_code = self.service.set_new_email(self.phone_credentials, "newemail@newemail.com")
        new_email_credentials = Credentials()
        new_email_credentials.set_email("newemail@newemail.com")
        new_email_credentials.set_password(self.phone_credentials.password)
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(new_email_credentials))
        self.service.authentificate(self.phone_credentials)
        self.service.verify_email(self.phone_credentials, verification_code)
        self.service.authentificate(new_email_credentials)
        self.service.authentificate(self.phone_credentials)

    def test_set_and_verify_new_phone_when_phone_verified(self):
        verification_code = self.service.set_new_phone(self.phone_credentials, "+79212225577")
        new_phone_credentials = Credentials()
        new_phone_credentials.set_phone("+79212225577")
        new_phone_credentials.set_password(self.phone_credentials.password)
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(new_phone_credentials))
        self.service.authentificate(self.phone_credentials)
        self.service.verify_phone(self.phone_credentials, verification_code)
        self.service.authentificate(new_phone_credentials)
        self.assertRaises(IncorrectLogin, lambda: self.service.authentificate(self.phone_credentials))