
"""
    hello
"""

from envi import Request, Application as EnviApplication
from controllers import AuthController

application = EnviApplication()
application.route("/<action>/", AuthController)