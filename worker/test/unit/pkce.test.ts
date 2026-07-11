import { describe, it, expect } from "vitest";
import { verifyPkceS256 } from "../../src/lib/pkce";

describe("PKCE S256", () => {
  // RFC 7636 Appendix B known-answer vector.
  const verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
  const challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

  it("accepts a matching verifier/challenge", async () => {
    expect(await verifyPkceS256(verifier, challenge)).toBe(true);
  });

  it("rejects a wrong verifier", async () => {
    expect(await verifyPkceS256("not-the-verifier", challenge)).toBe(false);
  });

  it("rejects a wrong challenge", async () => {
    expect(await verifyPkceS256(verifier, "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA")).toBe(
      false,
    );
  });
});
