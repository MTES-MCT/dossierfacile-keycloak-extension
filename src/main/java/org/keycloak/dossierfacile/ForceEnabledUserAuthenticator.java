package org.keycloak.dossierfacile;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.authenticators.directgrant.AbstractDirectGrantAuthenticator;
import org.keycloak.models.AuthenticationExecutionModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.provider.ProviderConfigProperty;

import java.util.ArrayList;
import java.util.List;


public class ForceEnabledUserAuthenticator extends AbstractDirectGrantAuthenticator {
    private static final Logger log = Logger.getLogger(ForceEnabledUserAuthenticator.class);
    private static final String PROVIDER_ID = "force-enable-user";

    private static final AuthenticationExecutionModel.Requirement[] REQUIREMENT_CHOICES = {
            AuthenticationExecutionModel.Requirement.REQUIRED,
            AuthenticationExecutionModel.Requirement.DISABLED};

    private static final List<ProviderConfigProperty> configProperties = new ArrayList<>();

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        UserModel userModel = context.getUser();

        String email = userModel.getEmail();
        log.info(String.format("Email found is: %s", email));

        /// do enable operation
        if (!context.getUser().isEnabled()) {
            log.warn("User is not enabled - force it: " + email);
            context.getUser().setEnabled(true);
        }

        context.success();
    }

    @Override
    public boolean requiresUser() {
        return false;
    }

    @Override
    public boolean configuredFor(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {
        return false;
    }

    @Override
    public void setRequiredActions(KeycloakSession keycloakSession, RealmModel realmModel, UserModel userModel) {

    }

    @Override
    public List<RequiredActionFactory> getRequiredActions(KeycloakSession session) {
        return null;
    }

    @Override
    public String getDisplayType() {
        return "Enable user - force";
    }

    @Override
    public String getReferenceCategory() {
        return null;
    }

    @Override
    public boolean isConfigurable() {
        return false;
    }

    @Override
    public AuthenticationExecutionModel.Requirement[] getRequirementChoices() {
        return REQUIREMENT_CHOICES;
    }

    @Override
    public boolean isUserSetupAllowed() {
        return false;
    }

    @Override
    public String getHelpText() {
        return "Allow to enable user";
    }

    @Override
    public List<ProviderConfigProperty> getConfigProperties() {
        return configProperties;
    }

    @Override
    public String getId() {
        return PROVIDER_ID;
    }
}
