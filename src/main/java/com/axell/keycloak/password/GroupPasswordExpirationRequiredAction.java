package com.axell.keycloak.password;

import java.util.Optional;
import org.keycloak.Config;
import org.keycloak.authentication.RequiredActionContext;
import org.keycloak.authentication.RequiredActionFactory;
import org.keycloak.authentication.RequiredActionProvider;
import org.keycloak.credential.CredentialModel;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.models.UserModel;

public class GroupPasswordExpirationRequiredAction implements RequiredActionProvider, RequiredActionFactory {

    public static final String ID = "group-password-expiration-check";
    private static final long DAY_MILLIS = 24L * 60L * 60L * 1000L;

    @Override
    public void evaluateTriggers(RequiredActionContext context) {
        Object raw = context.getRealm().getPasswordPolicy().getPolicyConfig(GroupPasswordPolicyProviderFactory.ID);
        if (raw == null) {
            return;
        }

        GroupPasswordPolicyConfig.ParsedPolicyBundle bundle;
        try {
            bundle = GroupPasswordPolicyConfig.parse(raw.toString());
        } catch (IllegalArgumentException ex) {
            return;
        }

        GroupPasswordPolicyConfig.PolicyEntry policy = GroupPasswordPolicyConfig.resolvePolicy(bundle, context.getUser());
        if (policy == null || policy.expireDays == null) {
            return;
        }

        Optional<CredentialModel> passwordCredential = context.getUser().credentialManager()
            .getStoredCredentialsByTypeStream(CredentialModel.PASSWORD)
            .findFirst();

        if (passwordCredential.isEmpty()) {
            context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
            return;
        }

        Long createdDate = passwordCredential.get().getCreatedDate();
        if (createdDate == null) {
            context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
            return;
        }

        long ageMillis = System.currentTimeMillis() - createdDate;
        long expiryMillis = policy.expireDays.longValue() * DAY_MILLIS;
        if (ageMillis >= expiryMillis) {
            context.getUser().addRequiredAction(UserModel.RequiredAction.UPDATE_PASSWORD);
        }
    }

    @Override
    public void requiredActionChallenge(RequiredActionContext context) {
        context.success();
    }

    @Override
    public void processAction(RequiredActionContext context) {
        context.success();
    }

    @Override
    public RequiredActionProvider create(KeycloakSession session) {
        return this;
    }

    @Override
    public void init(Config.Scope config) {
    }

    @Override
    public void postInit(KeycloakSessionFactory factory) {
    }

    @Override
    public void close() {
    }

    @Override
    public String getId() {
        return ID;
    }

    @Override
    public String getDisplayText() {
        return "Group password expiration check";
    }
}
