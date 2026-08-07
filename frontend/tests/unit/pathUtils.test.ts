import { describe, expect, it } from "vitest";
import {
  encodePath,
  decodePath,
  joinPath,
  parentPath,
  splitCrumbs,
  prefixToPath,
  roleEntryPath,
  clampPathToEntry,
} from "@/utils/pathUtils";

describe("encodePath / decodePath", () => {
  it("roundtrips simple paths", () => {
    const p = "foo/bar/baz.txt";
    expect(decodePath(encodePath(p))).toBe(p);
  });

  it("preserves colon, hash, question mark in keys", () => {
    const p = "logs/2026-04-30T15:00:00.log";
    expect(decodePath(encodePath(p))).toBe(p);
  });

  it("preserves spaces and unicode", () => {
    const p = "фото/отпуск 🏖️.jpg";
    expect(decodePath(encodePath(p))).toBe(p);
  });

  it("encodes / as path separator (does NOT encode it)", () => {
    // We need slashes to remain slashes for breadcrumb display logic,
    // so encodePath splits on / and encodeURIComponent each segment.
    const encoded = encodePath("foo/bar baz/qux:1.txt");
    expect(encoded).toBe("foo/bar%20baz/qux%3A1.txt");
  });
});

describe("joinPath", () => {
  it("joins segments with /", () => {
    expect(joinPath("foo", "bar", "baz")).toBe("foo/bar/baz");
  });

  it("strips leading/trailing slashes from each segment", () => {
    expect(joinPath("/foo/", "/bar/", "/baz/")).toBe("foo/bar/baz");
  });

  it("ignores empty segments", () => {
    expect(joinPath("foo", "", "bar")).toBe("foo/bar");
  });

  it("returns empty string for no segments", () => {
    expect(joinPath()).toBe("");
  });
});

describe("parentPath", () => {
  it("removes last segment", () => {
    expect(parentPath("foo/bar/baz.txt")).toBe("foo/bar");
  });

  it("returns empty string for top-level file", () => {
    expect(parentPath("baz.txt")).toBe("");
  });

  it("returns empty string for empty input", () => {
    expect(parentPath("")).toBe("");
  });
});

describe("splitCrumbs", () => {
  it("returns array of {name, path} for breadcrumbs", () => {
    expect(splitCrumbs("foo/bar/baz")).toEqual([
      { name: "foo", path: "foo" },
      { name: "bar", path: "foo/bar" },
      { name: "baz", path: "foo/bar/baz" },
    ]);
  });

  it("returns empty array for empty path", () => {
    expect(splitCrumbs("")).toEqual([]);
  });
});

describe("prefix entry helpers", () => {
  it("prefixToPath strips slashes", () => {
    expect(prefixToPath("stand-dayna/")).toBe("stand-dayna");
    expect(prefixToPath("/stand-dayna/")).toBe("stand-dayna");
  });

  it("roleEntryPath only for a single prefix", () => {
    expect(roleEntryPath(["stand-dayna/"])).toBe("stand-dayna");
    expect(roleEntryPath(["a/", "b/"])).toBe("");
    expect(roleEntryPath(undefined)).toBe("");
  });

  it("clampPathToEntry never climbs above the entry prefix", () => {
    expect(clampPathToEntry("", "stand-dayna")).toBe("stand-dayna");
    expect(clampPathToEntry("stand-dayna/sprites", "stand-dayna")).toBe(
      "stand-dayna/sprites",
    );
    expect(clampPathToEntry("other", "stand-dayna")).toBe("stand-dayna");
    expect(clampPathToEntry("stand-dayna-evil", "stand-dayna")).toBe("stand-dayna");
  });
});
