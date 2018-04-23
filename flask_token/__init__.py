"""
flask token 
--------------
参考了 flask_jwt https://github.com/mattupstate/flask-jwt/blob/master/flask_jwt/__init__.py
"""

import functools
from flask import current_app, request, _request_ctx_stack
from werkzeug.local import LocalProxy
from itsdangerous import (TimedJSONWebSignatureSerializer
                          as Serializer, BadSignature, SignatureExpired)

__version__ = '0.0.1'

app_token = LocalProxy(lambda: current_app.extensions['app_token'])


def make_token(payload, exp=600):
    """ Make a token."""
    s = Serializer(
        current_app.config['SECRET_KEY'],
        expires_in=exp
    )
    token = s.dumps(payload)
    return token.decode('utf-8')


def parse_token(token):
    """ parse a token."""
    s = Serializer(current_app.config['SECRET_KEY'])
    try:
        data = s.loads(token)
    except SignatureExpired as e:
        raise e
    except BadSignature:
        raise e
    return data


def get_http_header_token():
    """ 获取http头部携带的token"""
    token_value = request.headers.get('Authorization', None)
    token_type = 'Bearer'
    if not token_value:
        return
    
    parts = token_value.split()

    if parts[0].lower() != token_type.lower():
        raise TokenError('Invalid Token header', 'Unsupported authorization type')
    elif len(parts) == 1:
        raise TokenError('Invalid Token header', 'Token missing')
    elif len(parts) > 2:
        raise TokenError('Invalid Token header', 'Token contains spaces')

    return parts[1]


def _token_required():
    """ 判断token有效性"""
    # 从请求头中获取token
    token = get_http_header_token()
    if token is None:
        raise TokenError(
            'Authorization Required',
            'Request does not contain an access token'
        )

    # 解析payload
    payload = parse_token(token)
    if payload is None:
        raise TokenError('Invalid Token', 'Invalid Token')

    _request_ctx_stack.top.current_identity = identity = app_token.identity_callback(payload)
    if identity is None:
        raise TokenError('Invalid Token', 'User does not exist')


def token_required(func):
    """ 检测请求是否包含token"""

    @functools.wraps(func)
    def decorator(*args, **kw):
        _token_required()
        return func(*args, **kw)
    return decorator


class Token(object):

    def __init__(
        self, app=None,
        authentication_handler=None, identity_handler=None
    ):
        # 用户认证回调和用户信息回调
        self.authentication_callback = authentication_handler
        self.identity_callback = identity_handler

        # 创建token回调和解析token回调
        self.make_token_callback = make_token
        self.parse_token_callbak = parse_token

        if app is not None:
            self.init_app(app)

    def init_app(self, app):
        """ 初始化扩展"""

        if not hasattr(app, 'extensions'):
            app.extensions = {}

        app.extensions['app_token'] = self
    
    def authentication_handler(self, callback):
        """ 指定用户认证回调"""
        self.authentication_callback = callback
        return callback
    
    def identity_handler(self, callback):
        """ 指定用户信息回调"""
        self.identity_callback = callback
        return callback


class TokenError(Exception):
    def __init__(self, error, description, status_code=401, headers=None):
        self.error = error
        self.description = description
        self.status_code = status_code
        self.headers = headers

    def __repr__(self):
        return 'TokenError: {}'.format(self.error)

    def __str__(self):
        return '{0}. {1}'.format(self.error, self.description)