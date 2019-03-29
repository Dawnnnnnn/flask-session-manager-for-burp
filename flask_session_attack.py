# coding=utf-8
from burp import IBurpExtender
from burp import IContextMenuFactory
from burp import IBurpExtenderCallbacks
from burp import IHttpRequestResponse
from burp import IHttpListener

from javax.swing import JMenuItem
from javax.swing import JOptionPane

import zlib
import ast
from itsdangerous import base64_decode
from flask.sessions import SecureCookieSessionInterface


class MockApp(object):

    def __init__(self, secret_key):
        self.secret_key = secret_key


def session_cookie_encoder(secret_key, session_cookie_structure):
    """ Encode a Flask session cookie """
    try:
        app = MockApp(secret_key)

        session_cookie_structure = dict(ast.literal_eval(session_cookie_structure))
        si = SecureCookieSessionInterface()
        s = si.get_signing_serializer(app)

        return s.dumps(session_cookie_structure)
    except Exception as e:
        return "[Encoding error]{}".format(e)


def session_cookie_decoder(session_cookie_value, secret_key=None):
    """ Decode a Flask cookie  """
    try:
        if (secret_key == None):
            compressed = False
            payload = session_cookie_value

            if payload.startswith(b'.'):
                compressed = True
                payload = payload[1:]

            data = payload.split(".")[0]

            data = base64_decode(data)
            if compressed:
                data = zlib.decompress(data)

            return data
        else:
            app = MockApp(secret_key)

            si = SecureCookieSessionInterface()
            s = si.get_signing_serializer(app)

            return s.loads(session_cookie_value)
    except Exception as e:
        return "[Decoding error]{}".format(e)


def decode(cookie, secret_key):
    print(session_cookie_decoder(cookie, secret_key))


def encode(cookie_structure,secret_key):
    print(session_cookie_encoder(secret_key,cookie_structure))



class BurpExtender(IBurpExtender, IHttpListener, IContextMenuFactory, IHttpRequestResponse,
                   IBurpExtenderCallbacks):

    def registerExtenderCallbacks(self, callbacks):
        self._actionName = "decode_flask_session"
        self._actionName1 = "encode_flask_session"
        self._helers = callbacks.getHelpers()
        self._callbacks = callbacks
        callbacks.setExtensionName("flask_session_manager")
        callbacks.registerHttpListener(self)
        callbacks.registerContextMenuFactory(self)

        return

    def createMenuItems(self, invocation):
        menu = []
        responses = invocation.getSelectedMessages()
        if len(responses) == 1:
            menu.append(
                JMenuItem(self._actionName, None, actionPerformed=lambda x, inv=invocation: self.decode_session(inv)))
            menu.append(JMenuItem(self._actionName1,None,actionPerformed=lambda x: self.encode_session()))
            return menu
        return None

    def decode_session(self, invocation):
        secret_key = JOptionPane.showInputDialog(None, "secret_key:", "input", JOptionPane.QUESTION_MESSAGE)
        invMessage = invocation.getSelectedMessages()
        request = invMessage[0].getRequest().tostring()
        select_msg_index = invocation.getSelectionBounds()
        select_cookie = request[select_msg_index[0]:select_msg_index[1]]
        decode(select_cookie, secret_key)

    def encode_session(self):
        cookie_structure = JOptionPane.showInputDialog(None, "cookie_structure:", "input", JOptionPane.QUESTION_MESSAGE)
        secret_key = JOptionPane.showInputDialog(None, "secret_key:", "input", JOptionPane.QUESTION_MESSAGE)
        encode(cookie_structure, secret_key)


