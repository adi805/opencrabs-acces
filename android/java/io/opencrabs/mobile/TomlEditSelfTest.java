package io.opencrabs.mobile;

/**
 * Regression checks for {@link TomlEdit}, run by the android-artifact workflow.
 *
 * <p>This shell has no JUnit and no gradle test task: android/assemble-apk.sh
 * compiles the Java sources with javac, so a test that actually runs has to be a
 * main() the workflow invokes. Every case below is a bug that was real. The
 * duplicate-key case is the one that mattered: saving settings wrote a second
 * copy of a key into a file the core then refused to parse, which looks like the
 * core being broken rather than the editor.
 */
public final class TomlEditSelfTest {

    private static int failures;

    private TomlEditSelfTest() {}

    public static void main(String[] args) {
        // A tab is whitespace in TOML exactly like a space.
        String tabbed = "[agent]\ndefault_model\t= \"old\"\n";
        String out = TomlEdit.setKey(tabbed, "agent", "default_model", "\"new\"");
        check("tab before = replaces in place", out,
            "[agent]\ndefault_model = \"new\"\n");
        check("tab before = leaves one key", count(out, "default_model"), 1);

        // The forms that already worked must keep working.
        check("space before = replaces",
            TomlEdit.setKey("[agent]\nmodel = \"a\"\n", "agent", "model", "\"b\""),
            "[agent]\nmodel = \"b\"\n");
        check("header with a comment is found",
            TomlEdit.setKey("[agent] # defaults\nmodel = \"a\"\n", "agent", "model", "\"b\""),
            "[agent] # defaults\nmodel = \"b\"\n");

        // A key that merely starts with the name is a different key.
        check("prefix key is not the key",
            TomlEdit.setKey("[agent]\nmodel_name = \"a\"\n", "agent", "model", "\"b\""),
            "[agent]\nmodel = \"b\"\nmodel_name = \"a\"\n");

        // A missing section is created; a '#' inside a value is not a comment.
        check("missing section is created",
            TomlEdit.setKey("", "providers.x", "api_key", "\"k\""),
            "[providers.x]\napi_key = \"k\"\n");
        check("hash inside a value is kept",
            TomlEdit.setKey("[a]\nk = \"#notacomment\"\n", "a", "k", "\"v\""),
            "[a]\nk = \"v\"\n");

        if (failures > 0) {
            System.out.println("FAIL: " + failures + " case(s)");
            System.exit(1);
        }
        System.out.println("OK: TomlEdit self-test, 6 cases");
    }

    private static void check(String name, String actual, String expected) {
        if (expected.equals(actual)) {
            return;
        }
        failures++;
        System.out.println("FAIL " + name);
        System.out.println("  expected: " + escape(expected));
        System.out.println("  actual  : " + escape(actual));
    }

    private static void check(String name, int actual, int expected) {
        if (actual == expected) {
            return;
        }
        failures++;
        System.out.println("FAIL " + name + " (expected " + expected + ", got " + actual + ")");
    }

    private static int count(String haystack, String needle) {
        int n = 0;
        int i = 0;
        while ((i = haystack.indexOf(needle, i)) >= 0) {
            n++;
            i += needle.length();
        }
        return n;
    }

    private static String escape(String s) {
        return s.replace("\n", "\\n").replace("\t", "\\t");
    }
}
