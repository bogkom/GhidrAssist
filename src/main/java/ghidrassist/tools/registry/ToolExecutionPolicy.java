package ghidrassist.tools.registry;

import java.util.Map;
import java.util.Set;

/** Explicit controller input. Natural-language objectives are not parsed into this policy. */
public final class ToolExecutionPolicy {
    private final Set<String> allowedTools; // null means unrestricted; an empty set denies all.
    private final Map<String, Integer> perToolLimits;
    private final Integer totalLimit;
    private final boolean readOnly;

    public ToolExecutionPolicy(Set<String> allowedTools, Map<String, Integer> perToolLimits) {
        this(allowedTools, perToolLimits, null, false);
    }

    public ToolExecutionPolicy(Set<String> allowedTools, Map<String, Integer> perToolLimits, Integer totalLimit, boolean readOnly) {
        if (totalLimit != null && totalLimit < 0) throw new IllegalArgumentException("Global budget must be nonnegative");
        this.totalLimit = totalLimit;
        this.readOnly = readOnly;
        if (allowedTools != null) allowedTools.forEach(ToolExecutionPolicy::validateName);
        perToolLimits.forEach((name, limit) -> {
            validateName(name);
            if (limit == null || limit < 0) throw new IllegalArgumentException("Tool budgets must be nonnegative");
        });
        this.allowedTools = allowedTools == null ? null : Set.copyOf(allowedTools);
        this.perToolLimits = Map.copyOf(perToolLimits);
    }

    private static void validateName(String name) {
        if (name == null || name.isBlank()) throw new IllegalArgumentException("Tool name must not be blank");
    }

    public static ToolExecutionPolicy unrestricted() { return new ToolExecutionPolicy(null, Map.of()); }
    public boolean allows(String toolName) { return allowedTools == null || allowedTools.contains(toolName); }
    public Integer totalLimit() { return totalLimit; }
    public boolean readOnly() { return readOnly; }
    public Integer limit(String toolName) { return perToolLimits.get(toolName); }
}
