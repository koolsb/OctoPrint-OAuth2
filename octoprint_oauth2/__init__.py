import datetime
import os
import secrets

import requests
from flask import Blueprint, redirect, request, session, url_for
from flask_login import login_user
from oauthlib.oauth2 import InsecureTransportError, WebApplicationClient

from octoprint.events import eventManager, Events
from octoprint.server.util.flask import session_signature
import octoprint.plugin

# OAuth2 Plugin integrates OAuth2 authentication into OctoPrint
class OAuth2Plugin(
    octoprint.plugin.AssetPlugin,
    octoprint.plugin.MfaPlugin,
    octoprint.plugin.StartupPlugin,
    octoprint.plugin.SettingsPlugin,
    octoprint.plugin.TemplatePlugin,
    octoprint.plugin.BlueprintPlugin,
    octoprint.plugin.RestartNeedingPlugin,
):
    
    def __init__(self):
        # Initialize plugin attributes
        self.client = None
        self.openid_config = None

    def on_after_startup(self):
        # Log plugin startup and initialize OAuth2 client
        self._logger.info("OAuth2 Plugin Started")
        self._initialize_oauth_client()

    def on_settings_save(self, data):
        # Save settings and reinitialize OAuth2 client
        super().on_settings_save(data)
        self._initialize_oauth_client()
        
    def is_blueprint_protected(self):
        # Allow public access to blueprint routes
        return False
    
    @octoprint.plugin.BlueprintPlugin.route("/login", methods=["GET"])
    def login(self):
        # Initiate OAuth2 login flow
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
        # Handle OAuth2 callback and complete authentication
        if not self.openid_config:
            return "OpenID configuration missing", 500
        
        state = session.get("state")
        if not state or state != request.args.get("state"):
            return "Invalid state parameter", 400
        
        code = request.args.get("code")
        if not code:
            return "No code provided", 400
        
        if not self._fetch_token(code):
            return "Failed to fetch token", 500
        
        user_info = self._fetch_user_info()
        if not user_info:
            return "Failed to fetch user info", 500
        
        groups = user_info.get("groups", [])
        
        if not self._validate_user_groups(groups):
            self._logger.error("User not in required group")
            return "Unauthorized", 403

        local_user = self._map_user(user_info) or self._create_user(user_info)
        if not local_user:
            self._logger.error(f"Failed to create or map user: {user_info}")
            return "Failed to find user", 500
        
        self._map_user_groups(local_user.get_id(), groups)
        
        if not self._login_user(local_user):
            self._logger.error("Failed to login user")
            return "Login Failed", 500
            
        return redirect(url_for("login"))
        
    def get_assets(self):
        # Provide client-side assets
        return {
            "clientjs": ["js/oauth2_client.js"],
        }

    def get_settings_defaults(self):
        # Define default settings for the plugin
        return {
            "client_id": None,
            "client_secret": None,
            "well_known_url": None,
            "group_mapping": {"admins": None, "operator": None, "readonly": None},
            "allow_insecure_transport": False,
            "provider_name": "OAuth2 Provider",
            "auto_redirect": False,
        }
    
    def get_template_configs(self):
        # Define UI templates for settings and login
        return [
            dict(type="settings", custom_bindings=False),
            dict(type="usersettings", name="Access", replaces="access", template="oauth2_access.jinja2", custom_bindings=False),
            dict(type="mfa_login", template="oauth2_login.jinja2", name="redirect" if self._settings.get(["auto_redirect"]) else self._settings.get(["provider_name"]))
        ]
    
    def get_template_vars(self):
        # Provide template variables for UI
        return dict(session=session)    

    def get_update_information(self):
        # Provide plugin update informatino for OctoPrint's Software Updater
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
    
    def _initialize_oauth_client(self):
        # Initialize OAuth2 client and load OpenID configuration
        if self._settings.get_boolean(["allow_insecure_transport"]):
            self._logger.warning("Insecure transport enabled")
            os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"
        else:
            os.environ.pop("OAUTHLIB_INSECURE_TRANSPORT", None)
        
        well_known_url = self._settings.get(["well_known_url"])

        try:
            response = requests.get(well_known_url)
            response.raise_for_status()
            self.openid_config = response.json()

        except requests.RequestException as e:
            self._logger.error("Error fetching OpenID config: %s", e)
            self.openid_config = None

        self.client = WebApplicationClient(self._settings.get(["client_id"]))

    def _fetch_token(self, code):
        # Fetch OAuth2 token using authorization code
        try: 
            token_url = self.openid_config["token_endpoint"]

            _, _, token_request_data = self.client.prepare_token_request(
                token_url,
                authorization_response=request.url,
                redirect_url=url_for("plugin.oauth2.callback", _external=True),
                code=code,
            )

            token_response = requests.post(
                token_url,
                data=token_request_data,
                headers={"Content-Type": "application/x-www-form-urlencoded"},
                auth=(self._settings.get(["client_id"]), self._settings.get(["client_secret"]))
            )

            token_response.raise_for_status()
            self.client.parse_request_body_response(token_response.text)
            return True

        except (requests.RequestException, InsecureTransportError) as e:
            self._logger.error(f"Error fetching token: {e}")
            return False
        
    def _fetch_user_info(self):
        # Fetch user info using OAuth2 token
        try:
            userinfo_url = self.openid_config["userinfo_endpoint"]
            userinfo_response = requests.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {self.client.token['access_token']}"}
            )

            userinfo_response.raise_for_status()
            return userinfo_response.json()
        
        except requests.RequestException as e:
            self._logger.error(f"Error fetching user info: {e}")
            return None
        
    def _login_user(self, local_user):
        # Login user and update session data
        try:
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
            return True
        except Exception as e:
            self._logger.error(f"Error logging in user: {e}")
            return False
            
    def _create_user(self, user_info):
        # Create new user using OAuth user info
        username = user_info.get("preferred_username")
        if not username:
            self._logger.error("No username found in user info")
            return None
        
        self._logger.info(f"Creating new user: {username}")

        password = secrets.token_urlsafe(32)

        try:
            self._user_manager.add_user(username, password, True, None, None)
            self._logger.info(f"User created: {username}")
            return self._user_manager.findUser(username)
        
        except Exception as e:
            self._logger.error(f"Error creating user: {e}")
            return None
        
    def _map_user(self, user_info):
        # Map OAuth user to existing local user
        username = user_info.get("preferred_username")

        if not username:
            self._logger.error("No username found in user info")
            return None
        
        return self._user_manager.findUser(username)
        
    def _map_user_groups(self, username, groups):
        # Map OAuth user groups to local user groups
        group_mapping = {
            "admins": self._settings.get(["group_mapping", "admins"]),
            "users": self._settings.get(["group_mapping", "operator"]),
            "readonly": self._settings.get(["group_mapping", "readonly"]),
        }
       
        assigned_groups = [
           group for group, group_name in group_mapping.items() if group_name in groups
        ]

        try:
            self._user_manager.change_user_groups(username, assigned_groups)
            self._logger.info(f"User {username} groups updated to: {assigned_groups}")
            
        except Exception as e:
            self._logger.error(f"Error updating user groups: {e}")

    def _validate_user_groups(self, groups):
        # Validate user groups against allowed groups
        allowed_groups = {
            self._settings.get(["group_mapping", "admins"]),
            self._settings.get(["group_mapping", "operator"]),
            self._settings.get(["group_mapping", "readonly"])
        }

        return bool(allowed_groups.intersection(groups))

__plugin_name__ = "OAuth2 Plugin"

__plugin_pythoncompat__ = ">=3,<4"  # Only Python 3

def __plugin_load__():
    global __plugin_implementation__
    __plugin_implementation__ = OAuth2Plugin()

    global __plugin_hooks__
    __plugin_hooks__ = {
        "octoprint.plugin.softwareupdate.check_config": __plugin_implementation__.get_update_information,
    }
