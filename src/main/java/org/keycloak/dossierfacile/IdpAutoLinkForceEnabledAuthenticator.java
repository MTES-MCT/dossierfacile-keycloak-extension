package org.keycloak.dossierfacile;

import org.jboss.logging.Logger;
import org.keycloak.authentication.AuthenticationFlowContext;
import org.keycloak.authentication.AuthenticationFlowError;
import org.keycloak.authentication.AuthenticationFlowException;
import org.keycloak.authentication.Authenticator;
import org.keycloak.authentication.authenticators.broker.util.ExistingUserInfo;
import org.keycloak.authentication.authenticators.broker.util.SerializedBrokeredIdentityContext;
import org.keycloak.broker.provider.BrokeredIdentityContext;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.sessions.AuthenticationSessionModel;

import javax.ws.rs.core.Response;


public class IdpAutoLinkForceEnabledAuthenticator implements Authenticator {
    private static final Logger log = Logger.getLogger(IdpAutoLinkForceEnabledAuthenticator.class);
    private final KeycloakSession session;

    public IdpAutoLinkForceEnabledAuthenticator(KeycloakSession session) {
        this.session = session;
    }

    private static UserModel getExistingUser(KeycloakSession session, RealmModel realm, AuthenticationSessionModel authSession) {
        String existingUserId = authSession.getAuthNote("EXISTING_USER_INFO");
        if (existingUserId == null) {
            throw new AuthenticationFlowException("Unexpected state. There is no existing duplicated user identified in ClientSession", AuthenticationFlowError.INTERNAL_ERROR);
        }
        ExistingUserInfo duplication = ExistingUserInfo.deserialize(existingUserId);
        UserModel existingUser = session.users().getUserById(realm, duplication.getExistingUserId());
        if (existingUser == null) {
            throw new AuthenticationFlowException("User with ID '" + existingUserId + "' not found.", AuthenticationFlowError.INVALID_USER);
        }
        return existingUser;

    }

    private void sendFailureChallenge(AuthenticationFlowContext context, Response.Status status, String eventError, String errorMessage, AuthenticationFlowError flowError) {
        context.getEvent().user(context.getUser()).error(eventError);
        Response challengeResponse = context.form().setError(errorMessage).createErrorPage(status);
        context.failureChallenge(flowError, challengeResponse);
    }

    @Override
    public void authenticate(AuthenticationFlowContext context) {
        AuthenticationSessionModel authSession = context.getAuthenticationSession();
        SerializedBrokeredIdentityContext serializedCtx = SerializedBrokeredIdentityContext.readFromAuthenticationSession(authSession, "BROKERED_CONTEXT");
        if (serializedCtx == null) {
            throw new AuthenticationFlowException("Not found serialized context in clientSession", AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
        }
        BrokeredIdentityContext brokerContext = serializedCtx.deserialize(context.getSession(), authSession);
        if (!brokerContext.getIdpConfig().isEnabled()) {
            this.sendFailureChallenge(context, Response.Status.BAD_REQUEST, "identity_provider_error", "identityProviderUnexpectedErrorMessage", AuthenticationFlowError.IDENTITY_PROVIDER_ERROR);
        }
        KeycloakSession session = context.getSession();
        RealmModel realm = context.getRealm();

        UserModel existingUser = getExistingUser(session, realm, authSession);
        if (!existingUser.isEnabled()) {
            log.warnf("User is disable - FC connect then force enabled '%s' ", existingUser.getUsername());
            existingUser.setEnabled(true);
            existingUser.setEmailVerified(true);
        }

        context.setUser(existingUser);
        context.success();

    }

    @Override
    public void action(AuthenticationFlowContext authenticationFlowContext) {
        log.warn("Call action on IdpAutoLinkForceEnabledAuthenticator is not allowed !");
    }

    @Override
    public void close() {
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
}