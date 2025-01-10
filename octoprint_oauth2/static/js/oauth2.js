/*
 * View model for OpenID OAuth2 Authentication
 *
 * Author: Ben Kools
 * License: AGPLv3
 */
$(function() {
    function Oauth2ViewModel(parameters) {
        var self = this;

        // assign the injected parameters, e.g.:
        self.loginStateViewModel = parameters[0];
        // self.settingsViewModel = parameters[1];

        // TODO: Implement your plugin's view model here.
        self.showOAuthButton = () => {
            $("#mfa_login_oauth2").appendTo("login").show();
        };

        self.onStartupComplete = () => {
            alert('here');
            self.showOAuth2Button();
        }
    }

    /* view model class, parameters for constructor, container to bind to
     * Please see http://docs.octoprint.org/en/master/plugins/viewmodels.html#registering-custom-viewmodels for more details
     * and a full list of the available options.
     */
    OCTOPRINT_VIEWMODELS.push({
        construct: Oauth2ViewModel,
        // ViewModels your plugin depends on, e.g. loginStateViewModel, settingsViewModel, ...
        dependencies: ["loginStateViewModel", "settingsViewModel"],
        // Elements to bind to, e.g. #settings_plugin_oauth2, #tab_plugin_oauth2, ...
        elements: [ /* ... */ ]
    });
});
