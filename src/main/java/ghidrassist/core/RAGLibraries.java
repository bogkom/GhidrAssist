package ghidrassist.core;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import ghidra.framework.preferences.Preferences;
import ghidra.program.model.listing.Program;
import java.lang.reflect.Type;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;

/** Global library catalog and project-specific active library checkboxes. */
public final class RAGLibraries {
    public static final String UNIVERSAL = "universal";
    private static final String CATALOG_KEY = "GhidrAssist.RAGLibraries.v1";
    private static final String ACTIVE_PREFIX = "GhidrAssist.RAGActive.v1.";
    private static final Gson GSON = new Gson();
    private static final Type LIST_TYPE = new TypeToken<List<Library>>() {}.getType();
    private static final Type IDS_TYPE = new TypeToken<List<String>>() {}.getType();

    public static final class Library {
        public String id;
        public String name;
        public Library(String id, String name) { this.id = id; this.name = name; }
        @Override public String toString() { return name; }
    }

    private RAGLibraries() {}

    public static synchronized List<Library> list() {
        List<Library> result = null;
        try {
            result = GSON.fromJson(Preferences.getProperty(CATALOG_KEY, ""), LIST_TYPE);
        } catch (RuntimeException ignored) { /* Older/malformed preference */ }
        if (result == null) result = new ArrayList<>();
        List<Library> valid = new ArrayList<>();
        valid.add(new Library(UNIVERSAL, "Uniwersalna"));
        Set<String> ids = new LinkedHashSet<>(Collections.singleton(UNIVERSAL));
        for (Library item : result) {
            if (item != null && item.id != null && item.name != null &&
                !item.name.isBlank() && !item.id.equals(UNIVERSAL) && ids.add(item.id)) {
                valid.add(item);
            }
        }
        return valid;
    }

    private static void save(List<Library> libraries) {
        Preferences.setProperty(CATALOG_KEY, GSON.toJson(libraries));
        Preferences.store();
    }

    public static synchronized Set<String> allIds() {
        Set<String> result = new LinkedHashSet<>();
        for (Library lib : list()) result.add(lib.id);
        return result;
    }

    public static synchronized String nameOf(String id) {
        for (Library lib : list()) if (lib.id.equals(id)) return lib.name;
        return id;
    }

    private static void validateName(String name, String excludeId) {
        if (name == null || name.isBlank() || name.length() > 80) {
            throw new IllegalArgumentException("Library name must contain 1-80 characters.");
        }
        for (Library lib : list()) {
            if (!lib.id.equals(excludeId) && lib.name.equalsIgnoreCase(name.trim())) {
                throw new IllegalArgumentException("A library with this name already exists.");
            }
        }
    }

    public static synchronized String create(String name) {
        validateName(name, null);
        String id = UUID.randomUUID().toString();
        List<Library> libraries = list();
        libraries.add(new Library(id, name.trim()));
        save(libraries);
        return id;
    }

    public static synchronized void rename(String id, String name) {
        if (UNIVERSAL.equals(id)) throw new IllegalArgumentException("Universal library cannot be renamed.");
        validateName(name, id);
        List<Library> libraries = list();
        boolean found = false;
        for (Library lib : libraries) if (lib.id.equals(id)) {
            lib.name = name.trim(); found = true; break;
        }
        if (!found) throw new IllegalArgumentException("Unknown library.");
        save(libraries);
    }

    /** Call only after documents have been moved out of this library. */
    public static synchronized void delete(String id) {
        if (UNIVERSAL.equals(id)) throw new IllegalArgumentException("Universal library cannot be deleted.");
        List<Library> libraries = list();
        if (!libraries.removeIf(lib -> lib.id.equals(id))) throw new IllegalArgumentException("Unknown library.");
        save(libraries);
    }

    private static String activeKey(Program program) {
        String identity = "no-program";
        if (program != null) {
            String project = "";
            String path = "";
            if (program.getDomainFile() != null) {
                if (program.getDomainFile().getProjectLocator() != null)
                    project = program.getDomainFile().getProjectLocator().toString();
                path = program.getDomainFile().getPathname();
            }
            identity = project + "|" + path + "|" + program.getExecutableSHA256();
        }
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(identity.getBytes(StandardCharsets.UTF_8));
            StringBuilder result = new StringBuilder(ACTIVE_PREFIX);
            for (byte b : digest) result.append(String.format("%02x", b & 0xff));
            return result.toString();
        } catch (Exception e) {
            throw new IllegalStateException("Unable to identify Ghidra project", e);
        }
    }

    public static synchronized Set<String> active(Program program) {
        String stored = Preferences.getProperty(activeKey(program), null);
        // Existing GhidrAssist installations: old untagged documentation remains active.
        if (stored == null) return new LinkedHashSet<>(Collections.singleton(UNIVERSAL));
        List<String> saved;
        try { saved = GSON.fromJson(stored, IDS_TYPE); }
        catch (RuntimeException e) { saved = null; }
        if (saved == null) return new LinkedHashSet<>(Collections.singleton(UNIVERSAL));
        Set<String> valid = allIds();
        Set<String> result = new LinkedHashSet<>();
        for (String id : saved) if (valid.contains(id)) result.add(id);
        return result;
    }

    public static synchronized void setActive(Program program, Set<String> selected) {
        Set<String> valid = allIds();
        Set<String> result = new LinkedHashSet<>();
        for (String id : selected) if (valid.contains(id)) result.add(id);
        Preferences.setProperty(activeKey(program), GSON.toJson(new ArrayList<>(result)));
        Preferences.store();
    }
}
