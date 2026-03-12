package com.axell.keycloak.password;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
import java.util.Comparator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import org.keycloak.models.GroupModel;
import org.keycloak.models.RoleModel;
import org.keycloak.models.UserModel;

final class GroupPasswordPolicyConfig {

    static final String GROUP_PREFIX = "group:";
    static final String ROLE_PREFIX = "role:";
    private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();

    private GroupPasswordPolicyConfig() {
    }

    static ParsedPolicyBundle parse(String rawConfig) {
        String trimmed = rawConfig == null ? "" : rawConfig.trim();
        if (trimmed.startsWith("{")) {
            return parseJsonBundle(trimmed);
        }
        return parseLegacyBundle(rawConfig);
    }

    private static ParsedPolicyBundle parseLegacyBundle(String rawConfig) {
        String[] entries = rawConfig.split(";");
        List<PolicyEntry> policies = new ArrayList<>();

        for (String entry : entries) {
            String normalizedEntry = entry.trim();
            if (normalizedEntry.isEmpty()) {
                continue;
            }
            int equalsPos = normalizedEntry.indexOf('=');
            if (equalsPos < 0) {
                throw new IllegalArgumentException("Missing '=' separator in: " + normalizedEntry);
            }

            String key = normalizedEntry.substring(0, equalsPos).trim();
            String rules = normalizedEntry.substring(equalsPos + 1).trim();
            validateKey(key);
            if (rules.isEmpty()) {
                throw new IllegalArgumentException("Rules cannot be empty for key: " + key);
            }

            PolicyEntry policy = new PolicyEntry(key);
            for (String rule : rules.split(",")) {
                String normalizedRule = rule.trim();
                if (normalizedRule.isEmpty()) {
                    continue;
                }
                int colonPos = normalizedRule.indexOf(':');
                if (colonPos < 0) {
                    throw new IllegalArgumentException("Missing ':' separator in rule: " + normalizedRule);
                }

                String ruleKey = normalizedRule.substring(0, colonPos).trim().toLowerCase(Locale.ROOT);
                String value = normalizedRule.substring(colonPos + 1).trim();
                applyRule(policy, ruleKey, value);
            }
            policies.add(policy);
        }

        return new ParsedPolicyBundle(policies);
    }

    private static ParsedPolicyBundle parseJsonBundle(String rawConfig) {
        List<PolicyEntry> policies = new ArrayList<>();
        Map<String, Map<String, Object>> root;
        try {
            root = OBJECT_MAPPER.readValue(rawConfig, new TypeReference<Map<String, Map<String, Object>>>() {});
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException("Invalid JSON configuration", ex);
        }

        for (Map.Entry<String, Map<String, Object>> entry : root.entrySet()) {
            String key = entry.getKey() == null ? "" : entry.getKey().trim();
            validateKey(key);

            Map<String, Object> rules = entry.getValue();
            if (rules == null || rules.isEmpty()) {
                throw new IllegalArgumentException("Rules cannot be empty for key: " + key);
            }

            PolicyEntry policy = new PolicyEntry(key);
            for (Map.Entry<String, Object> ruleEntry : rules.entrySet()) {
                String ruleKey = ruleEntry.getKey() == null ? "" : ruleEntry.getKey().trim().toLowerCase(Locale.ROOT);
                Object rawValue = ruleEntry.getValue();
                if (ruleKey.isEmpty() || rawValue == null) {
                    continue;
                }
                applyRule(policy, ruleKey, String.valueOf(rawValue));
            }
            policies.add(policy);
        }

        return new ParsedPolicyBundle(policies);
    }

    private static void validateKey(String key) {
        if (key == null || key.isEmpty()) {
            throw new IllegalArgumentException("Key cannot be empty");
        }
        if ("*".equals(key) || key.startsWith(GROUP_PREFIX) || key.startsWith(ROLE_PREFIX)) {
            return;
        }
        throw new IllegalArgumentException(
            "Invalid key '" + key + "'. Keys must be '*', 'group:<path>', or 'role:<name>'");
    }

    /**
     * Resolves the single best-matching policy for the given user.
     *
     * All entries whose key matches the user (wildcard, group, or role) are collected.
     * The winner is chosen by:
     *   1. Most fields set (highest count wins).
     *   2. On a tie, highest restrictiveness score wins — defined as the sum of all
     *      min* values (minLength + minLowerCase + minUpperCase + minDigits + minSpecialChars).
     */
    static PolicyEntry resolvePolicy(ParsedPolicyBundle bundle, UserModel user) {
        List<String> groupPaths = user.getGroupsStream()
            .map(GroupPasswordPolicyConfig::toPath)
            .collect(Collectors.toList());

        Set<String> roleNames = user.getRealmRoleMappingsStream()
            .map(RoleModel::getName)
            .collect(Collectors.toSet());

        List<PolicyEntry> candidates = new ArrayList<>();

        for (PolicyEntry policy : bundle.policies) {
            if ("*".equals(policy.key)) {
                candidates.add(policy);
            } else if (policy.key.startsWith(ROLE_PREFIX)) {
                String roleName = policy.key.substring(ROLE_PREFIX.length());
                if (roleNames.contains(roleName)) {
                    candidates.add(policy);
                }
            } else if (policy.key.startsWith(GROUP_PREFIX)) {
                String groupPath = "/" + policy.key.substring(GROUP_PREFIX.length());
                for (String userGroupPath : groupPaths) {
                    if (userGroupPath.equals(groupPath) || userGroupPath.startsWith(groupPath + "/")) {
                        candidates.add(policy);
                        break;
                    }
                }
            }
        }

        return candidates.stream()
            .max(Comparator.comparingInt(GroupPasswordPolicyConfig::countFields)
                .thenComparingInt(GroupPasswordPolicyConfig::restrictiveness))
            .orElse(null);
    }

    private static int countFields(PolicyEntry e) {
        int count = 0;
        if (e.minLength != null)    count++;
        if (e.maxLength != null)    count++;
        if (e.minLowerCase != null) count++;
        if (e.minUpperCase != null) count++;
        if (e.minDigits != null)    count++;
        if (e.minSpecialChars != null) count++;
        if (e.notUsername)          count++;
        if (e.regex != null)        count++;
        if (e.expireDays != null)   count++;
        return count;
    }

    private static int restrictiveness(PolicyEntry e) {
        int score = 0;
        if (e.minLength != null)      score += e.minLength;
        if (e.minLowerCase != null)   score += e.minLowerCase;
        if (e.minUpperCase != null)   score += e.minUpperCase;
        if (e.minDigits != null)      score += e.minDigits;
        if (e.minSpecialChars != null) score += e.minSpecialChars;
        return score;
    }

    private static String toPath(GroupModel group) {
        LinkedList<String> parts = new LinkedList<>();
        GroupModel current = group;
        while (current != null) {
            parts.addFirst(current.getName());
            current = current.getParent();
        }
        return "/" + String.join("/", parts);
    }

    private static void applyRule(PolicyEntry policy, String key, String value) {
        switch (key) {
            case "minlength":
                policy.minLength = parsePositiveInteger(key, value);
                break;
            case "maxlength":
                policy.maxLength = parsePositiveInteger(key, value);
                break;
            case "minlowercase":
            case "minlowercasechars":
                policy.minLowerCase = parseNonNegativeInteger(key, value);
                break;
            case "minuppercase":
            case "minuppercasechars":
                policy.minUpperCase = parseNonNegativeInteger(key, value);
                break;
            case "mindigits":
                policy.minDigits = parseNonNegativeInteger(key, value);
                break;
            case "minspecialchars":
                policy.minSpecialChars = parseNonNegativeInteger(key, value);
                break;
            case "notusername":
                policy.notUsername = Boolean.parseBoolean(value);
                break;
            case "regex":
                try {
                    policy.regex = Pattern.compile(value);
                } catch (PatternSyntaxException ex) {
                    throw new IllegalArgumentException("Invalid regex pattern: " + value, ex);
                }
                break;
            case "expiredays":
                policy.expireDays = parsePositiveInteger(key, value);
                break;
            default:
                throw new IllegalArgumentException("Unsupported rule: " + key);
        }
    }

    private static int parsePositiveInteger(String key, String value) {
        int number = Integer.parseInt(value);
        if (number <= 0) {
            throw new IllegalArgumentException("Rule " + key + " must be > 0");
        }
        return number;
    }

    private static int parseNonNegativeInteger(String key, String value) {
        int number = Integer.parseInt(value);
        if (number < 0) {
            throw new IllegalArgumentException("Rule " + key + " must be >= 0");
        }
        return number;
    }

    static final class PolicyEntry {
        final String key;
        Integer minLength;
        Integer maxLength;
        Integer minLowerCase;
        Integer minUpperCase;
        Integer minDigits;
        Integer minSpecialChars;
        boolean notUsername;
        Pattern regex;
        Integer expireDays;

        PolicyEntry(String key) {
            this.key = key;
        }
    }

    static final class ParsedPolicyBundle {
        final List<PolicyEntry> policies;

        ParsedPolicyBundle(List<PolicyEntry> policies) {
            this.policies = policies;
        }
    }
}
