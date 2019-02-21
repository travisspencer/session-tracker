import ssl
import time
import urllib
import urllib2

from flask import Flask, render_template, request, json, session as flask_sesion, abort

app = Flask(__name__)

oauth_server = "https://localhost:8443"
authorize_uri = "/authorize"
token_uri = "/token"
client_id = "www"
client_secret = "Password1"
scope = ""
logout_uri = "/authentication/logout"

scim_client_id = "admin"
scim_client_secret = "Password1"
scim_delegation_uri = "/um/admin/Delegations"
scim_token_uri = "/admin/token"

introspect_client_id = "gateway_client"
introspect_client_secret = "Password1"
introspect_uri = "/introspection"


def get_scim_access_token():
    data = {
        "client_id": scim_client_id,
        "client_secret": scim_client_secret,
        "grant_type": "client_credentials"
    }
    token_response = urllib2.urlopen(urllib2.Request("%s%s" % (oauth_server, scim_token_uri), urllib.urlencode(data)),
                                     context=ssl_context())
    token_response_json = json.loads(token_response.read())

    return token_response_json.get("access_token", "")


def get_all_sessions_for_user(username):
    resources = delegations = []

    if username:
        flask_sesion["username"] = username
    else:
        return delegations

    data = {
        "attributes": "externalId,id,sub,exp,clientId"
    }
    scim_access_token = get_scim_access_token()

    if scim_access_token:
        scim_response = urllib2.urlopen(
            urllib2.Request("%s%s?%s" % (oauth_server, scim_delegation_uri, urllib.urlencode(data)),
                            headers=dict(Authorization="bearer %s" % scim_access_token)),
            context=ssl_context())
        scim_response_json = json.loads(scim_response.read())

        resources = scim_response_json.get("Resources", [])

    for resource in resources:
        if resource.get("sub", "") == username:
            # See if there's already a delegation with the same ID in the session because that one will have the
            # access and refresh token
            for existing_delegation in flask_sesion.get("delegations", []):
                if existing_delegation["id"] == resource["id"]:
                    resource = existing_delegation

            delegations.append(resource)

    return delegations


@app.route("/delete")
def delete():
    if "all" not in request.args and "id" not in request.args:
        abort(400)

    delegations = []

    if "all" in request.args:
        # Get all the sessions from the SCIM server right now in case new sessions have been initiated at some other
        # client. The ones in the current session may not be all of them.
        for delegation in get_all_sessions_for_user(flask_sesion.get("username", [])):
            delete_delegation(delegation["id"])

        return logout()
    elif "id" in request.args:
        delegation_id = request.args["id"]
        delete_delegation(delegation_id)
        delegations = flask_sesion["delegations"] = [d for d in flask_sesion["delegations"] if
                                                     d.get("id", None) != delegation_id]

    return render_template("index.html",
                           authorization_uri="%s%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%scb" % (
                               oauth_server, authorize_uri, client_id, scope, request.host_url),
                           delegations=delegations,
                           username=flask_sesion["username"],
                           logout_uri="%s%s?redirect_uri=%slogout" % (oauth_server, logout_uri, request.host_url))


def delete_delegation(delegation_id):
    scim_access_token = get_scim_access_token()

    delete_request = urllib2.Request("%s%s/%s" % (oauth_server, scim_delegation_uri, delegation_id),
                                     headers=dict(Authorization="bearer %s" % scim_access_token))
    delete_request.get_method = lambda: 'DELETE'
    response_code = -1

    try:
        scim_response = urllib2.urlopen(delete_request, context=ssl_context())
        response_code = scim_response.code
    except urllib2.HTTPError as e:
        if e.code != 404:
            raise e

    return response_code == 200


@app.route("/introspect")
def introspect():
    if "access_token" not in request.args or not request.args["access_token"]:
        return "No token in request"

    data = {'client_id': introspect_client_id, "client_secret": introspect_client_secret,
            'token': request.args["access_token"]
            }
    try:
        introspection_response = urllib2.urlopen(
            urllib2.Request("%s%s" % (oauth_server, introspect_uri), urllib.urlencode(data), headers=dict(
                Accept="application/jwt")), context=ssl_context())

        if introspection_response.code == 200:
            return "Introspection succeeded"
        elif introspection_response.code == 204:
            return "Token is revoked or unknown"
        else:
            return "Introspection was not possible"
    except urllib2.HTTPError as e:
        print e

        return "Failed to introspect token due to an error"


@app.route("/refresh")
def refresh():
    if "refresh_token" not in request.args or not request.args["refresh_token"]:
        return "No refresh token in request"

    data = {'client_id': client_id, "client_secret": client_secret,
            'refresh_token': request.args["refresh_token"],
            "grant_type": "refresh_token"
            }
    try:
        token_response = urllib2.urlopen(
            urllib2.Request("%s%s" % (oauth_server, token_uri), urllib.urlencode(data)), context=ssl_context())

        if token_response.code == 200:
            return "Refresh succeeded"
        else:
            return "Refresh was not possible"
    except urllib2.HTTPError as e:
        if e.code != 400:
            raise e

    return "Failed to refresh token due to an error"


@app.route('/cb')
def callback():
    code = request.args["code"]
    delegations = flask_sesion.get("delegations", [])

    if code:
        data = {'client_id': client_id, "client_secret": client_secret,
                'code': code,
                'redirect_uri': request.base_url,
                'grant_type': 'authorization_code'}
        try:
            token_response = urllib2.urlopen(
                urllib2.Request("%s%s" % (oauth_server, token_uri), urllib.urlencode(data)),
                context=ssl_context())
            token_response_json = json.loads(token_response.read())

            # Save all delegations returned from the SCIM server in the user's session
            flask_sesion["username"] = username = token_response_json.get("sub", None)
            delegations = get_all_sessions_for_user(username)

            delegation_id = token_response_json.get("delegation_id", None)

            if delegation_id:
                for d in delegations:
                    if d["externalId"] == delegation_id:
                        d["access_token"] = token_response_json["access_token"]
                        d["refresh_token"] = token_response_json["refresh_token"]

            flask_sesion["delegations"] = delegations
        except urllib2.HTTPError as e:
            if e.code == 400:
                # User probably refreshed the page.
                delegations = flask_sesion.get("delegations", [])
            else:
                raise e

    return render_template("index.html",
                           authorization_uri="%s%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%scb" % (
                               oauth_server, authorize_uri, client_id, scope, request.host_url),
                           delegations=delegations,
                           username=flask_sesion.get("username", ""),
                           logout_uri="%s%s?redirect_uri=%slogout" % (oauth_server, logout_uri, request.host_url))


def ssl_context():
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE

    return ctx


@app.route("/logout")
def logout():
    flask_sesion.clear()

    return index()


@app.route('/')
def index():
    return render_template("index.html",
                           authorization_uri="%s%s?client_id=%s&response_type=code&scope=%s&redirect_uri=%scb" % (
                               oauth_server, authorize_uri, client_id, scope, request.host_url))


if __name__ == '__main__':
    app.secret_key = b'changeme'
    app.jinja_env.filters['datetime'] = lambda value: time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(value))
    app.run(debug=True)
