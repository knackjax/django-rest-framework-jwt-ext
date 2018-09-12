from rest_framework_jwt.views import ObtainJSONWebToken

from .serializers import UserJWTSerializer


class ObtainUserJWT(ObtainJSONWebToken):
    serializer_class = UserJWTSerializer


obtain_user_jwt = ObtainUserJWT.as_view()
