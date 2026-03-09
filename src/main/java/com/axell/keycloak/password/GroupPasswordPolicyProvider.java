package com.axell.keycloak.password;

import org.keycloak.models.RealmModel;
import org.keycloak.models.UserModel;
import org.keycloak.policy.PasswordPolicyProvider;
import org.keycloak.policy.PolicyError;

public class GroupPasswordPolicyProvider implements PasswordPolicyProvider {

    private final GroupPasswordPolicyProviderFactory factory;

    public GroupPasswordPolicyProvider(GroupPasswordPolicyProviderFactory factory) {
        this.factory = factory;
    }

    @Override
    public PolicyError validate(RealmModel realm, UserModel user, String password) {
        Object raw = realm.getPasswordPolicy().getPolicyConfig(factory.getId());
        if (raw == null || password == null || user == null) {
            return null;
        }

        GroupPasswordPolicyConfig.ParsedPolicyBundle bundle;
        try {
            bundle = GroupPasswordPolicyConfig.parse(raw.toString());
        } catch (IllegalArgumentException ex) {
            return new PolicyError("invalidPasswordPolicyConfigMessage");
        }

        GroupPasswordPolicyConfig.GroupPolicy policy = GroupPasswordPolicyConfig.resolvePolicy(bundle, user);
        if (policy == null) {
            return null;
        }

        if (policy.notUsername && password.equalsIgnoreCase(user.getUsername())) {
            return new PolicyError("invalidPasswordNotUsernameMessage");
        }

        if (policy.minLength != null && password.length() < policy.minLength) {
            return new PolicyError("invalidPasswordMinLengthMessage", policy.minLength);
        }

        if (policy.maxLength != null && password.length() > policy.maxLength) {
            return new PolicyError("invalidPasswordMaxLengthMessage", policy.maxLength);
        }

        if (policy.minLowerCase != null && countByType(password, CharacterType.LOWERCASE) < policy.minLowerCase) {
            return new PolicyError("invalidPasswordMinLowerCaseCharsMessage", policy.minLowerCase);
        }

        if (policy.minUpperCase != null && countByType(password, CharacterType.UPPERCASE) < policy.minUpperCase) {
            return new PolicyError("invalidPasswordMinUpperCaseCharsMessage", policy.minUpperCase);
        }

        if (policy.minDigits != null && countByType(password, CharacterType.DIGIT) < policy.minDigits) {
            return new PolicyError("invalidPasswordMinDigitsMessage", policy.minDigits);
        }

        if (policy.minSpecialChars != null && countByType(password, CharacterType.SPECIAL) < policy.minSpecialChars) {
            return new PolicyError("invalidPasswordMinSpecialCharsMessage", policy.minSpecialChars);
        }

        if (policy.regex != null && !policy.regex.matcher(password).matches()) {
            return new PolicyError("invalidPasswordRegexPatternMessage", policy.regex.pattern());
        }

        return null;
    }

    @Override
    public PolicyError validate(String user, String password) {
        return null;
    }

    @Override
    public Object parseConfig(String value) {
        if (value == null || value.isBlank()) {
            return null;
        }
        GroupPasswordPolicyConfig.parse(value);
        return value;
    }

    @Override
    public void close() {
    }

    private int countByType(String password, CharacterType type) {
        int count = 0;
        for (int i = 0; i < password.length(); i++) {
            char current = password.charAt(i);
            if (type.matches(current)) {
                count++;
            }
        }
        return count;
    }

    private enum CharacterType {
        LOWERCASE {
            @Override
            boolean matches(char character) {
                return Character.isLowerCase(character);
            }
        },
        UPPERCASE {
            @Override
            boolean matches(char character) {
                return Character.isUpperCase(character);
            }
        },
        DIGIT {
            @Override
            boolean matches(char character) {
                return Character.isDigit(character);
            }
        },
        SPECIAL {
            @Override
            boolean matches(char character) {
                return !Character.isLetterOrDigit(character);
            }
        };

        abstract boolean matches(char character);
    }

}
