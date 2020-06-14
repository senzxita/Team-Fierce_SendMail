from flask import request, jsonify
from config import app
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
import jwt
import datetime
from functools import wraps
from models import Users


#Generate and validate access token
def token_required(f):
    @wraps(f)
    def decorator(*args, **kwargs):

      token = None
      
      if 'x-access-tokens' in request.headers:
          token = request.headers['x-access-tokens']
      
      if not token:
          return jsonify({
                'status': 'unauthorized',
                'data':{
                    'message': 'a valid token is required for this request'
                }
            }), 404

      try:
          data = jwt.decode(token, connex_app.config['SECRET_KEY'])
          current_user = Users.query.filter_by(public_id=data['public_id']).first()
      except:
        return jsonify({
                'status': 'unauthorized',
                'data':{
                    'message': 'token is invalid.'
                }
            }), 404
        return f(current_user, *args, **kwargs)
    return decorator