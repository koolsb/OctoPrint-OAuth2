# coding=utf-8
from __future__ import absolute_import

import os
import secrets
import string
import datetime
import requests

from flask import Blueprint, redirect, url_for, request, session, render_template, make_response
from flask_login import login_user
from oauthlib.oauth2 import WebApplicationClient
from octoprint.events import Events, eventManager
from octoprint.server.util.flask import session_signature
import octoprint.plugin

class OAuth2Plugin(
    octoprint.plugin.AssetPlugin,
    octoprint.plugin.MfaPlugin,
    octoprint.plugin.StartupPlugin,
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.TemplatePlugin,
    #octoprint.plugin.ReloadNeedingPlugin,
    octoprint.plugin.BlueprintPlugin,
):
    
    def __init__(self):
        self.client = None
        self.openid_config = None

    def on_after_startup(self):
        self._logger.info("OAuth2 Plugin Started")

        if self._settings.get_boolean(["allow_insecure_transport"]):
            os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
        
        well_known_url = self._settings.get(["well_known_url"])

        try:
            response = requests.get(well_known_url)
            response.raise_for_status()
            self.openid_config = response.json()

        except requests.RequestException as e:
            self._logger.error("OAuth2 Plugin: Error fetching OpenID config: %s", e)
            self.open_id_config = None

        self.client = WebApplicationClient(self._settings.get(["client_id"]))
        
    def get_settings_defaults(self):
        return {
            "client_id": None,
            "client_secret": None,
            "well_known_url": None,
            "group_mapping": {"admin_group": None, "operator_group": None, "readonly_group": None},
            "allow_insecure_transport": False,
            "provider_name": "OAuth2 Provider"
        }
    
    def get_template_configs(self):
        return [
            dict(type="settings", custom_bindings=False),
            dict(type="usersettings", name="Access", replaces="access", template="oauth2_access.jinja2", custom_bindings=False),
            dict(type="mfa_login", template="oauth2_test.jinja2")
        ]
    
    def get_template_vars(self):
        return dict(session=session)

    ##~~ AssetPlugin mixin

    def get_assets(self):
        # Define your plugin's asset files to automatically include in the
        # core UI here.
        return {
            "clientjs": ["js/oauth2.js"],
            #"css": ["css/oauth2.css"],
            #"less": ["less/oauth2.less"]
        }

    ##~~ Softwareupdate hook

    def get_update_information(self):
        # Define the configuration for your plugin to use with the Software Update
        # Plugin here. See https://docs.octoprint.org/en/master/bundledplugins/softwareupdate.html
        # for details.
        return {
            "oauth2": {
                "displayName": "OAuth2 Plugin",
                "displayVersion": self._plugin_version,

                # version check: github repository
                "type": "github_release",
                "user": "koolsb",
                "repo": "OctoPrint-OAuth2",
                "current": self._plugin_version,

                # update method: pip
                "pip": "https://github.com/koolsb/OctoPrint-OAuth2/archive/{target_version}.zip",
            }
        }
    
    def is_blueprint_protected(self):
        """Disable authentication requirement for this Blueprint."""
        return False
    
    @octoprint.plugin.BlueprintPlugin.route("/login", methods=["GET"])
    def login(self):
        if not self.client or not self.openid_config:
            return "OAuth2 client not initialized", 500
        
        authorization_url, _, _ = self.client.prepare_authorization_request(
            self.openid_config["authorization_endpoint"],
            redirect_url=url_for("plugin.oauth2.callback", _external=True),
            scope=["openid", "profile", "email"],
        )

        session["state"] = self.client.state
        return redirect(authorization_url)
    
    
    @octoprint.plugin.BlueprintPlugin.route("/callback", methods=["GET"])
    def callback(self):
        if not self.openid_config:
            return "OpenID configuration missing", 500
        
        state = session.get("state")
        if not state or state != request.args.get("state"):
            return "Invalid state parameter", 400
        
        code = request.args.get("code")
        if not code:
            return "No code provided", 400
        
        token_url = self.openid_config["token_endpoint"]

        try: 
            token_request_data = self.client.prepare_token_request(
                token_url,
                authorization_response=request.url,
                redirect_url=url_for("plugin.oauth2.callback", _external=True),
                code=code,
            )

            token_response = requests.post(
                token_url,
                data=token_request_data[2],
                headers={"content-Type": "application/x-www-form-urlencoded"},
                auth=(self._settings.get(["client_id"]), self._settings.get(["client_secret"]))
            )

            token_response.raise_for_status()
            self.client.parse_request_body_response(token_response.text)

        except requests.RequestException as e:
            self._logger.error(f"Error fetching token: {e}")
            return "Failed to fetch token", 500

        userinfo_url = self.openid_config["userinfo_endpoint"]

        try:
            userinfo_response = requests.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {self.client.token['access_token']}"}
            )
            userinfo_response.raise_for_status()
        except requests.RequestException as e:
            self._logger.error(f"Error fetching user info: {e}")
            return "Failed to fetch user info", 500
        
        user_info = userinfo_response.json()
        groups = user_info.get("groups", [])

        if not self._validate_user_groups(groups):
            self._logger.error("User not in required group")
            return "Unauthorized", 403

        local_user = self._map_user(user_info) or self._create_user(user_info)

        if not local_user:
            return "Failed to create or map user", 500
        
        self._map_user_groups(local_user.get_id(), groups)
        
        user = self._user_manager.login_user(local_user)
        self._user_manager.change_user_setting(user.get_id(), "login_mechanism", "openid")
        session.update({
            "usersession.id": user.session,
            "usersession.signature": session_signature(local_user.get_id(), user.session),
            "login_mechanism": "openid",
            "credentials_seen": datetime.datetime.now().timestamp()
        })

        login_user(user, remember=False)
        eventManager().fire(Events.USER_LOGGED_IN, payload={"username": local_user.get_id()})

        self._logger.info(f"User logged in: {local_user.get_id()}")

        self._logger.info("Session Variables on Login:")
        for key, value in session.items():
            self._logger.info(f"{key}: {value}")
            
        return redirect(url_for("login"))
    
    def _map_user(self, user_info):
        """Map OpenID user to a local OctoPrint user."""
        username = user_info.get("preferred_username")
        if not username:
            self._logger.error("No username found in user info")
            return None
        
        return self._user_manager.findUser(username)
    
    def _create_user(self, user_info):
        """Create a new local OctoPrint user."""
        username = user_info.get("preferred_username")
        if not username:
            self._logger.error("No username found in user info")
            return None
        
        self._logger.info(f"Creating new user: {username}")

        password = ''.join(secrets.choice(string.ascii_letters + string.digits) for _ in range(32))

        try:
            self._user_manager.add_user(username, password, True, None, None)
            self._logger.info(f"OAuth2 Plugin: User created: {username}")
            return self._user_manager.findUser(username)
        except Exception as e:
            self._logger.error(f"OAuth2 Plugin: Error creating user: {e}")
            return None
        
    def _map_user_groups(self, username, groups):
        """Map OpenID groups to local OctoPrint groups."""
        admin_group = self._settings.get(["group_mapping", "admin_group"])
        operator_group = self._settings.get(["group_mapping", "operator_group"])
        readonly_group = self._settings.get(["group_mapping", "readonly_group"])

        assigned_groups = []
        if admin_group and admin_group in groups:
            assigned_groups.append("admins")
        if operator_group and operator_group in groups:
            assigned_groups.append("users")
        if readonly_group and readonly_group in groups:
            assigned_groups.append("readonly")

        try:
            self._user_manager.change_user_groups(username, assigned_groups)
            self._logger.info(f"User {username} groups updated to: {assigned_groups}")
        except Exception as e:
            self._logger.error(f"Error updating user groups: {e}")

    def _validate_user_groups(self, groups):
        """Validate that the user is in the required group."""
        admin_group = self._settings.get(["group_mapping", "admin_group"])
        operator_group = self._settings.get(["group_mapping", "operator_group"])
        readonly_group = self._settings.get(["group_mapping", "readonly_group"])

        return admin_group in groups or operator_group in groups or readonly_group in groups


# If you want your plugin to be registered within OctoPrint under a different name than what you defined in setup.py
# ("OctoPrint-PluginSkeleton"), you may define that here. Same goes for the other metadata derived from setup.py that
# can be overwritten via __plugin_xyz__ control properties. See the documentation for that.
__plugin_name__ = "OAuth2 Plugin"


# Set the Python version your plugin is compatible with below. Recommended is Python 3 only for all new plugins.
# OctoPrint 1.4.0 - 1.7.x run under both Python 3 and the end-of-life Python 2.
# OctoPrint 1.8.0 onwards only supports Python 3.
__plugin_pythoncompat__ = ">=3,<4"  # Only Python 3

def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = OAuth2Plugin()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information,
    }
