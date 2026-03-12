package com.axell.keycloak.password;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.util.ArrayList;
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

            String key = normalizedEntry.substring(0, equalsPos).trim();
            String rules = normalizedEntry.substring(equalsPos + 1).trim();
            validateKey(key);
            if (rules.isEmpty()) {
                throw new IllegalArgumentException("Rules cannot be empty for key: " + key);
            }

            GroupPolicy policy = new GroupPolicy(key);
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
        List<GroupPolicy> policies = new ArrayList<>();
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

            GroupPolicy policy = new GroupPolicy(key);
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
        if ("*".equals(key) || key.startsWith(GROUP_PREFIX) || key.startsWith(ROLE_PREFIX) || key.startsWith("/")) {
            return;
        }
        throw new IllegalArgumentException(
            "Invalid key '" + key + "'. Keys must be '*', 'group:<path>', 'role:<name>', or legacy '/<path>'");
    }

    /**
     * Resolves the single best-matching policy for the given user.
     *
     * Priority tiers (highest first):
     *   1. Role entries  — if the user has any matching role:name entries, the best
     *                      one among them is used and groups/wildcard are ignored.
     *   2. Group entries — if no role matched, the best matching group:path entry is used.
     *   3. Wildcard "*"  — fallback when nothing else matches.
     *
     * Within a tier, the winner is chosen by:
     *   1. Most fields set (highest count wins).
     *   2. On a tie, highest restrictiveness score — sum of all min* values.
     */
    static GroupPolicy resolvePolicy(ParsedPolicyBundle bundle, UserModel user) {
        List<String> groupPaths = user.getGroupsStream()
            .map(GroupPasswordPolicyConfig::toPath)
            .collect(Collectors.toList());

        Set<String> roleNames = user.getRealmRoleMappingsStream()
            .map(RoleModel::getName)
            .collect(Collectors.toSet());

        GroupPolicy fallback = null;
        List<GroupPolicy> matchingGroups = new ArrayList<>();
        List<GroupPolicy> matchingRoles = new ArrayList<>();

        for (GroupPolicy policy : bundle.policies) {
            if ("*".equals(policy.key)) {
                fallback = policy;
            } else if (policy.key.startsWith(ROLE_PREFIX)) {
                String roleName = policy.key.substring(ROLE_PREFIX.length());
                if (roleNames.contains(roleName)) {
                    matchingRoles.add(policy);
                }
            } else if (policy.key.startsWith(GROUP_PREFIX) || policy.key.startsWith("/")) {
                String groupPath = policy.key.startsWith(GROUP_PREFIX)
                    ? "/" + policy.key.substring(GROUP_PREFIX.length())
                    : policy.key;
                for (String userGroupPath : groupPaths) {
                    if (userGroupPath.equals(groupPath) || userGroupPath.startsWith(groupPath + "/")) {
                        matchingGroups.add(policy);
                        break;
                    }
                }
            }
        }

        if (!matchingRoles.isEmpty()) {
            return best(matchingRoles);
        }
        if (!matchingGroups.isEmpty()) {
            return best(matchingGroups);
        }
        return fallback;
    }

    private static GroupPolicy best(List<GroupPolicy> candidates) {
        GroupPolicy winner = null;
        for (GroupPolicy candidate : candidates) {
            if (winner == null) {
                winner = candidate;
                continue;
            }
            int countDiff = countFields(candidate) - countFields(winner);
            if (countDiff > 0 || (countDiff == 0 && restrictiveness(candidate) > restrictiveness(winner))) {
                winner = candidate;
            }
        }
        return winner;
    }

    private static int countFields(GroupPolicy policy) {
        int count = 0;
        if (policy.minLength != null)       count++;
        if (policy.maxLength != null)       count++;
        if (policy.minLowerCase != null)    count++;
        if (policy.minUpperCase != null)    count++;
        if (policy.minDigits != null)       count++;
        if (policy.minSpecialChars != null) count++;
        if (policy.notUsername)             count++;
        if (policy.notEmail)                count++;
        if (policy.notRecentlyUsed != null) count++;
        if (policy.regex != null)           count++;
        if (policy.expireDays != null)      count++;
        return count;
    }

    private static int restrictiveness(GroupPolicy policy) {
        int score = 0;
        if (policy.minLength != null)       score += policy.minLength;
        if (policy.minLowerCase != null)    score += policy.minLowerCase;
        if (policy.minUpperCase != null)    score += policy.minUpperCase;
        if (policy.minDigits != null)       score += policy.minDigits;
        if (policy.minSpecialChars != null) score += policy.minSpecialChars;
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
            case "notemail":
                policy.notEmail = Boolean.parseBoolean(value);
                break;
            case "notrecentlyused":
                policy.notRecentlyUsed = parsePositiveInteger(key, value);
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
        final String key;
        Integer minLength;
        Integer maxLength;
        Integer minLowerCase;
        Integer minUpperCase;
        Integer minDigits;
        Integer minSpecialChars;
        boolean notUsername;
        boolean notEmail;
        Integer notRecentlyUsed;
        Pattern regex;
        Integer expireDays;

        GroupPolicy(String key) {
            this.key = key;
        }
    }

    static final class ParsedPolicyBundle {
        final List<GroupPolicy> policies;

        ParsedPolicyBundle(List<GroupPolicy> policies) {
            this.policies = policies;
        }
    }
}
