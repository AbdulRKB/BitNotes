import os

class Config:
    SECRET_KEY = 'hello-world'
    SESSION_TYPE = 'filesystem'
    SESSION_PERMANENT = False
    SESSION_USE_SIGNER = True
    DATABASE = os.path.join(os.path.abspath(os.path.dirname(__file__)), 'bitnotes.db')
