import logging
from django.contrib.auth import authenticate

from rest_framework import serializers
from rest_framework_jwt.serializers import JSONWebTokenSerializer, jwt_payload_handler, jwt_encode_handler


logger = logging.getLogger('rest_framework_elasticsearch_ext.serializers')


def get_client_ip(request):
    x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
    if x_forwarded_for:
        ip = x_forwarded_for.split(',')[0]
        logger.debug('found client ip in HTTP_X_FORWARDED_FOR: {}'.format(ip))
    else:
        ip = request.META.get('REMOTE_ADDR')
        logger.debug('found client ip in REMOTE_ADDR: {}'.format(ip))
    return ip


class UserJWTSerializer(JSONWebTokenSerializer):

    def validate(self, attrs):
        credentials = {
            self.username_field: attrs.get(self.username_field),
            'password': attrs.get('password')
        }

        if all(credentials.values()):
            user = authenticate(request=self.context['request'], **credentials)

            if user:
                if not user.is_active:
                    msg = 'User account is disabled.'
                    raise serializers.ValidationError(msg)

                payload = jwt_payload_handler(user)
                payload['client_ip'] = get_client_ip(self.context['request'])

                return {
                    'token': jwt_encode_handler(payload),
                    'user': user
                }
            else:
                msg = 'Unable to log in with provided credentials.'
                raise serializers.ValidationError(msg)
        else:
            msg = 'Must include "{username_field}" and "password".'
            msg = msg.format(username_field=self.username_field)
            raise serializers.ValidationError(msg)
