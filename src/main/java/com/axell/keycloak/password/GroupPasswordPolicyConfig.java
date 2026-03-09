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
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import java.util.stream.Collectors;
import org.keycloak.models.GroupModel;
import org.keycloak.models.UserModel;

final class GroupPasswordPolicyConfig {

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
        List<GroupPolicy> policies = new ArrayList<>();

        for (String entry : entries) {
            String normalizedEntry = entry.trim();
            if (normalizedEntry.isEmpty()) {
                continue;
            }
            int equalsPos = normalizedEntry.indexOf('=');
            if (equalsPos < 0) {
                throw new IllegalArgumentException("Missing '=' separator in: " + normalizedEntry);
            }

            String groupPath = normalizedEntry.substring(0, equalsPos).trim();
            String rules = normalizedEntry.substring(equalsPos + 1).trim();
            if (groupPath.isEmpty()) {
                throw new IllegalArgumentException("Group path cannot be empty");
            }
            if (rules.isEmpty()) {
                throw new IllegalArgumentException("Rules cannot be empty");
            }

            GroupPolicy policy = new GroupPolicy(groupPath);
            for (String rule : rules.split(",")) {
                String normalizedRule = rule.trim();
                if (normalizedRule.isEmpty()) {
                    continue;
                }
                int colonPos = normalizedRule.indexOf(':');
                if (colonPos < 0) {
                    throw new IllegalArgumentException("Missing ':' separator in rule: " + normalizedRule);
                }

                String key = normalizedRule.substring(0, colonPos).trim().toLowerCase(Locale.ROOT);
                String value = normalizedRule.substring(colonPos + 1).trim();
                applyRule(policy, key, value);
            }
            policies.add(policy);
        }

        policies.sort(Comparator.comparingInt(policy -> policy.groupPath.length()));
        return new ParsedPolicyBundle(policies);
    }

    private static ParsedPolicyBundle parseJsonBundle(String rawConfig) {
        List<GroupPolicy> policies = new ArrayList<>();
        Map<String, Map<String, Object>> root;
        try {
            root = OBJECT_MAPPER.readValue(rawConfig, new TypeReference<Map<String, Map<String, Object>>>() {});
        } catch (JsonProcessingException ex) {
            throw new IllegalArgumentException("Invalid JSON configuration", ex);
        }

        for (Map.Entry<String, Map<String, Object>> entry : root.entrySet()) {
            String groupPath = entry.getKey() == null ? "" : entry.getKey().trim();
            if (groupPath.isEmpty()) {
                throw new IllegalArgumentException("Group path cannot be empty");
            }

            Map<String, Object> rules = entry.getValue();
            if (rules == null || rules.isEmpty()) {
                throw new IllegalArgumentException("Rules cannot be empty for group: " + groupPath);
            }

            GroupPolicy policy = new GroupPolicy(groupPath);
            for (Map.Entry<String, Object> ruleEntry : rules.entrySet()) {
                String key = ruleEntry.getKey() == null ? "" : ruleEntry.getKey().trim().toLowerCase(Locale.ROOT);
                Object rawValue = ruleEntry.getValue();
                if (key.isEmpty() || rawValue == null) {
                    continue;
                }
                applyRule(policy, key, String.valueOf(rawValue));
            }
            policies.add(policy);
        }

        policies.sort(Comparator.comparingInt(policy -> policy.groupPath.length()));
        return new ParsedPolicyBundle(policies);
    }

    static GroupPolicy resolvePolicy(ParsedPolicyBundle bundle, UserModel user) {
        List<String> groupPaths = user.getGroupsStream()
            .map(GroupPasswordPolicyConfig::toPath)
            .collect(Collectors.toList());

        GroupPolicy best = null;
        int bestPathLength = -1;
        for (GroupPolicy policy : bundle.policies) {
            if ("*".equals(policy.groupPath)) {
                if (best == null) {
                    best = policy;
                }
                continue;
            }
            for (String userGroupPath : groupPaths) {
                if (userGroupPath.equals(policy.groupPath) || userGroupPath.startsWith(policy.groupPath + "/")) {
                    int currentLength = policy.groupPath.length();
                    if (currentLength > bestPathLength) {
                        best = policy;
                        bestPathLength = currentLength;
                    }
                }
            }
        }
        return best;
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

    private static void applyRule(GroupPolicy policy, String key, String value) {
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

    static final class GroupPolicy {
        final String groupPath;
        Integer minLength;
        Integer maxLength;
        Integer minLowerCase;
        Integer minUpperCase;
        Integer minDigits;
        Integer minSpecialChars;
        boolean notUsername;
        Pattern regex;
        Integer expireDays;

        GroupPolicy(String groupPath) {
            this.groupPath = groupPath;
        }
    }

    static final class ParsedPolicyBundle {
        final List<GroupPolicy> policies;

        ParsedPolicyBundle(List<GroupPolicy> policies) {
            this.policies = policies;
        }
    }
}
