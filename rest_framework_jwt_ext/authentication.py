import jwt
import logging

from django.utils.translation import ugettext as _
from rest_framework import exceptions

from rest_framework_jwt.settings import api_settings
from rest_framework_jwt.authentication import JSONWebTokenAuthentication
from .serializers import get_client_ip

jwt_decode_handler = api_settings.JWT_DECODE_HANDLER
jwt_get_username_from_payload = api_settings.JWT_PAYLOAD_GET_USERNAME_HANDLER

logger = logging.getLogger('rest_framework_elasticsearch_ext.authentication')


class AuthenticatedServiceClient:

    def __init__(self, username):
        self.username = username

    def is_authenticated(self):
        return True


class UserJWTAuthentication(JSONWebTokenAuthentication):

    def authenticate(self, request):
        """
        Returns a two-tuple of `User` and token if a valid signature has been
        supplied using JWT-based authentication.  Otherwise returns `None`.
        """
        jwt_value = self.get_jwt_value(request)
        if jwt_value is None:
            return None

        try:
            payload = jwt_decode_handler(jwt_value)
        except jwt.ExpiredSignature:
            msg = _('Signature has expired.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.DecodeError:
            msg = _('Error decoding signature.')
            raise exceptions.AuthenticationFailed(msg)
        except jwt.InvalidTokenError:
            raise exceptions.AuthenticationFailed()

        user = self.authenticate_credentials(payload)

        # Check client ip with payload
        request_client_ip = get_client_ip(request)
        payload_client_ip = payload['client_ip']
        logger.debug('client ip request vs payload: {} vs {}'.format(request_client_ip, payload_client_ip))
        if request_client_ip != payload_client_ip:
            msg = _('Client IP does not match with payload.')
            raise exceptions.AuthenticationFailed(msg)

        return (user, jwt_value)

    def get_jwt_value(self, request):
        """
        Override so only cookies are accepted
        """
        logger.debug("JWT_AUTH_COOKIE: {}".format(api_settings.JWT_AUTH_COOKIE))
        if api_settings.JWT_AUTH_COOKIE:
            logger.debug("JWT_AUTH_COOKIE VALUE: {}".format(request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)))
            return request.COOKIES.get(api_settings.JWT_AUTH_COOKIE)
        return None

    def authenticate_credentials(self, payload):
        """
        Returns an active user that matches the payload's user id and email.
        """
        username = jwt_get_username_from_payload(payload)

        if not username:
            msg = _('Invalid payload.')
            raise exceptions.AuthenticationFailed(msg)

        return AuthenticatedServiceClient(username)
