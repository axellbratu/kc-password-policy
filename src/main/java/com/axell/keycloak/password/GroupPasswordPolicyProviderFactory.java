package com.axell.keycloak.password;

import org.keycloak.Config;
import org.keycloak.models.KeycloakSession;
import org.keycloak.models.KeycloakSessionFactory;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PasswordPolicyProviderFactory;
import org.keycloak.provider.ProviderConfigProperty;

public class GroupPasswordPolicyProviderFactory implements PasswordPolicyProviderFactory {

    public static final String ID = "group-password-policy";
    private static final String DEFAULT_CONFIG = "{\n"
        + "  \"*\": { \"minLength\": 10, \"minDigits\": 1 },\n"
        + "  \"/customers\": { \"minLength\": 12, \"minDigits\": 1 },\n"
        + "  \"/backoffice\": { \"minLength\": 14, \"minDigits\": 1, \"minUpperCase\": 1, \"minLowerCase\": 1, \"minSpecialChars\": 1, \"expireDays\": 30 }\n"
        + "}";

    @Override
    public PasswordPolicyProvider create(KeycloakSession session) {
        return new GroupPasswordPolicyProvider(this);
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
    public String getDisplayName() {
        return "Group-based password policy";
    }

    @Override
    public String getConfigType() {
        return ProviderConfigProperty.TEXT_TYPE;
    }

    @Override
    public String getDefaultConfigValue() {
        return DEFAULT_CONFIG;
    }

    @Override
    public boolean isMultiplSupported() {
        return false;
    }
}
