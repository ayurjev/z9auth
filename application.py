
""" Микро-сервис для аутентификации

"""

from envi import Application as EnviApplication
from controllers import AuthController

application = EnviApplication()
application.route("/<action>/", AuthController)
application.route("/v1/<action>/", AuthController)