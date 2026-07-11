import { describe, it, expect } from "vitest";
import { generatePin, generateMagicToken, hashSecret, verifySecret } from "../../src/lib/otp";

describe("OTP + magic token", () => {
	it("always generates a 6-digit PIN", () => {
		for (let i = 0; i < 500; i++) {
			expect(generatePin()).toMatch(/^\d{6}$/);
		}
	});

	it("generates a 256-bit hex magic token", () => {
		expect(generateMagicToken()).toMatch(/^[0-9a-f]{64}$/);
	});

	it("hashes deterministically, salted by flow id", async () => {
		const a = await hashSecret("123456", "flow-1");
		const b = await hashSecret("123456", "flow-1");
		const c = await hashSecret("123456", "flow-2");
		expect(a).toBe(b);
		expect(a).not.toBe(c);
		expect(a).toMatch(/^[0-9a-f]{64}$/);
	});

	it("verifies the correct secret and rejects wrong secret or flow", async () => {
		const stored = await hashSecret("123456", "flow-1");
		expect(await verifySecret("123456", "flow-1", stored)).toBe(true);
		expect(await verifySecret("000000", "flow-1", stored)).toBe(false);
		expect(await verifySecret("123456", "flow-2", stored)).toBe(false);
	});
});
