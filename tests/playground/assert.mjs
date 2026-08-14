// Dependency-free assertion tally, so run-assets.mjs can run right after `npm run build` without
// pulling in the heavy playground/browser deps.
export function tally() {
	let failures = 0;
	return {
		check(name, cond, detail = "") {
			const ok = Boolean(cond);
			if (!ok) failures++;
			console.log(`  ${ok ? "✓" : "✗ FAIL"}  ${name}${detail ? ` — ${detail}` : ""}`);
			return ok;
		},
		get failures() {
			return failures;
		},
	};
}
