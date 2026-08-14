// Test D — the password-login block, against real WordPress core.
//
// This is the one thing the PHPUnit suite cannot fully prove. `authenticate` is a *filter*, not an
// action: every callback receives the previous one's return value and the last to run decides the
// outcome. Core registers wp_authenticate_username_password() and
// wp_authenticate_email_password() at priority 20. The plugin originally filtered at priority 1, so
// core ran *afterwards*, looked up the user by password, and handed back a WP_User — quietly
// overwriting the WP_Error the plugin had just returned. Password login worked the whole time.
//
// A hand-rolled fake WordPress cannot catch that, because the bug lives in core's own callbacks and
// the order they run in. So this suite boots real WordPress, creates a user with a real password,
// and tries every front door core exposes: the internal API, wp-login.php, and XML-RPC.
import { bootPlayground, phpJson } from "./lib.mjs";
import { tally } from "./assert.mjs";

const t = tally();

const USER = "victim";
const PASSWORD = "correct-horse-battery-staple";

console.log("Test D — direct password login is refused by real WordPress core");

const server = await bootPlayground({ port: 9412 });
try {
	const setup = await phpJson(
		server,
		`
		$id = wp_create_user(${JSON.stringify(USER)}, ${JSON.stringify(PASSWORD)}, 'victim@example.test');
		if (is_wp_error($id)) {
			return ['error' => $id->get_error_message()];
		}
		$user = new WP_User($id);
		$user->set_role('administrator');
		return ['id' => $id, 'mode' => JwtAuth\\Config::detectMode()->name];
		`,
	);
	t.check("test user created", !setup.error, setup.error ?? `id=${setup.id}`);
	t.check("plugin is in OIDC mode", setup.mode === "Oidc", `mode=${setup.mode}`);

	// ---------------------------------------------------------------------
	// The regression itself: who gets the last word on the filter
	// ---------------------------------------------------------------------

	const priorities = await phpJson(
		server,
		`
		global $wp_filter;
		$hook = $wp_filter['authenticate'] ?? null;
		if (!$hook) {
			return ['registered' => false];
		}
		$core = [];
		$ours = null;
		foreach ($hook->callbacks as $priority => $callbacks) {
			foreach ($callbacks as $entry) {
				$fn = $entry['function'];
				if (is_string($fn) && str_starts_with($fn, 'wp_authenticate_')) {
					$core[$fn] = $priority;
				}
				// The plugin registers a first-class callable, so this is a Closure rather than the
				// [class, method] array remove_filter()-style lookups expect. Both forms are matched
				// so the test describes the hook, not the syntax used to attach it.
				if ($fn instanceof Closure && (new ReflectionFunction($fn))->getName() === 'blockDirectAuth') {
					$ours = $priority;
				}
				if (is_array($fn) && ($fn[0] ?? null) === 'JwtAuth\\\\Validator') {
					$ours = $priority;
				}
			}
		}
		return ['registered' => true, 'core' => $core, 'ours' => $ours];
		`,
	);
	t.check("the plugin filters authenticate", priorities.registered && priorities.ours !== null);

	// Only the callbacks that turn a credential into a WP_User matter for ordering. Core also hooks
	// wp_authenticate_spam_check at 99, which runs after the block and is harmless: it can add an
	// error to a user, never resolve a password into one.
	const RESOLVERS = [
		"wp_authenticate_username_password",
		"wp_authenticate_email_password",
		"wp_authenticate_application_password",
	];
	const registered = priorities.core ?? {};
	const resolverPriorities = RESOLVERS.filter((fn) => fn in registered).map((fn) => registered[fn]);

	t.check(
		"core's own password callbacks are present to be beaten",
		resolverPriorities.length === RESOLVERS.length,
		Object.entries(registered)
			.map(([fn, p]) => `${fn}@${p}`)
			.join(", "),
	);
	t.check(
		"the block runs after every core callback that resolves a password",
		resolverPriorities.length > 0 && resolverPriorities.every((p) => priorities.ours > p),
		`ours=${priorities.ours}, resolvers at ${resolverPriorities.join("/")}`,
	);

	// Application passwords are the reason the list above includes a third entry: they are a second
	// password-shaped credential core accepts, on the same filter, and a block that only considered
	// the login form would leave them working.
	t.check(
		"application passwords are covered by the same ordering",
		registered["wp_authenticate_application_password"] !== undefined &&
			priorities.ours > registered["wp_authenticate_application_password"],
		`app passwords@${registered["wp_authenticate_application_password"]}`,
	);

	const laterThanOurs = Object.entries(registered).filter(([, p]) => p > priorities.ours);
	t.check(
		"nothing that runs later can resolve a credential into a user",
		laterThanOurs.every(([fn]) => !RESOLVERS.includes(fn)),
		laterThanOurs.map(([fn, p]) => `${fn}@${p}`).join(", ") || "nothing runs later",
	);

	// ---------------------------------------------------------------------
	// The outcome that actually matters
	// ---------------------------------------------------------------------

	const direct = await phpJson(
		server,
		`
		$result = wp_authenticate(${JSON.stringify(USER)}, ${JSON.stringify(PASSWORD)});
		return [
			'is_error' => is_wp_error($result),
			'is_user'  => $result instanceof WP_User,
			'code'     => is_wp_error($result) ? $result->get_error_code() : null,
			'message'  => is_wp_error($result) ? $result->get_error_message() : null,
		];
		`,
	);
	t.check(
		"a CORRECT password is refused by wp_authenticate()",
		direct.is_error && !direct.is_user,
		`code=${direct.code}`,
	);
	t.check(
		"and it is refused for the plugin's reason, not an incidental one",
		direct.code === "jwt_auth_required",
		`code=${direct.code}`,
	);
	t.check(
		"the refusal tells the user where to sign in instead",
		/Sign in with/i.test(direct.message ?? "") && /wp-login\.php/.test(direct.message ?? ""),
		direct.message ?? "",
	);

	// The control. Without this, "wp_authenticate refused the password" would also pass on a typo in
	// the fixture — a test that proves the plugin works by never presenting a valid credential at
	// all. Checked against the stored hash rather than by unhooking the filter, since the callback
	// is a Closure and no reconstructed remove_filter() call can match its identity.
	const credentials = await phpJson(
		server,
		`
		$user = get_user_by('login', ${JSON.stringify(USER)});
		return [
			'right' => wp_check_password(${JSON.stringify(PASSWORD)}, $user->user_pass, $user->ID),
			'wrong' => wp_check_password('not-the-password', $user->user_pass, $user->ID),
		];
		`,
	);
	t.check(
		"the password being refused is genuinely the user's password",
		credentials.right && !credentials.wrong,
		"otherwise the refusal above would prove nothing",
	);

	// ---------------------------------------------------------------------
	// wp-login.php — the front door, guarded by something else entirely
	// ---------------------------------------------------------------------
	//
	// Worth being precise about what this proves. In OIDC mode the plugin also hooks `login_init`
	// and bounces wp-login.php to the provider, so a POST here never reaches core's password
	// callbacks and would be refused even with blockDirectAuth removed. That is a genuine first line
	// of defence, and it is what the checks below measure — not the filter.
	//
	// It is also exactly why the filter has to exist. login_init only fires on wp-login.php, so
	// every other way into wp_authenticate() — XML-RPC, application passwords, any plugin calling
	// wp_signon() such as WooCommerce's AJAX login — walks straight past it.

	const loginUrl = new URL("/wp-login.php", server.serverUrl);
	const loginRes = await fetch(loginUrl, {
		method: "POST",
		headers: { "Content-Type": "application/x-www-form-urlencoded" },
		body: new URLSearchParams({
			log: USER,
			pwd: PASSWORD,
			"wp-submit": "Log In",
			redirect_to: new URL("/wp-admin/", server.serverUrl).href,
			testcookie: "1",
		}).toString(),
		redirect: "manual",
	});
	const setCookies = loginRes.headers.getSetCookie?.() ?? [];
	const authCookie = setCookies.find((c) => /^wordpress_logged_in[^=]*=[^;]+/.test(c));
	t.check(
		"POSTing valid credentials to wp-login.php issues no logged-in cookie",
		authCookie === undefined,
		authCookie ? `got ${authCookie.split("=")[0]}` : "no wordpress_logged_in cookie",
	);

	// wp-login.php answers a rejected login with a redirect back to itself, so the assertion that
	// matters is where it did *not* send the browser.
	const location = loginRes.headers.get("Location") ?? "";
	t.check(
		"and the browser is not sent into wp-admin",
		!/\/wp-admin\/?(\?|$)/.test(location),
		`Location: ${location || "(none)"}`,
	);

	// ---------------------------------------------------------------------
	// The IdP being unreachable must not break wp-login.php
	// ---------------------------------------------------------------------
	//
	// This suite's issuer is deliberately unroutable, which makes every request here a live test of
	// the degraded path: OIDC discovery fails, so login_init cannot redirect anywhere. It used to
	// throw, and an uncaught exception on wp-login.php is a 500 for every visitor whenever the
	// provider has a bad minute — or, with display_errors on, a stack trace full of absolute paths.
	//
	// Falling through to the ordinary login form is safe only because the filter is the real
	// defence; the checks above are what make that true.

	for (const [label, init] of [
		["GET", { redirect: "manual" }],
		[
			"POST",
			{
				method: "POST",
				headers: { "Content-Type": "application/x-www-form-urlencoded" },
				body: new URLSearchParams({ log: USER, pwd: PASSWORD, "wp-submit": "Log In" }).toString(),
				redirect: "manual",
			},
		],
	]) {
		const res = await fetch(loginUrl, init);
		const body = await res.text();
		t.check(
			`${label} wp-login.php survives an unreachable provider`,
			res.status < 500 && !/Fatal error/i.test(body) && !/Uncaught\s+\w*Exception/i.test(body),
			`HTTP ${res.status}${/Fatal error/i.test(body) ? " — PHP fatal in the body" : ""}`,
		);
		t.check(
			`${label} response leaks no filesystem paths`,
			!body.includes("/wp-content/plugins/jwt-auth/src/"),
			"a stack trace on an unauthenticated endpoint is free reconnaissance",
		);
	}

	// ---------------------------------------------------------------------
	// XML-RPC — the door people forget
	// ---------------------------------------------------------------------
	//
	// wp_xmlrpc_server::login() calls wp_authenticate(), so the block covers it — but only because
	// it wins the filter. At priority 1 this endpoint accepted the password like any other, which
	// is precisely the kind of thing a "we disabled password login" claim gets wrong.

	const xmlrpcEnabled = await phpJson(
		server,
		`return (bool) apply_filters('xmlrpc_enabled', true);`,
	);
	const xmlrpcRes = await fetch(new URL("/xmlrpc.php", server.serverUrl), {
		method: "POST",
		headers: { "Content-Type": "text/xml" },
		body: `<?xml version="1.0"?><methodCall><methodName>wp.getUsersBlogs</methodName><params><param><value><string>${USER}</string></value></param><param><value><string>${PASSWORD}</string></value></param></params></methodCall>`,
	});
	const xmlrpcBody = await xmlrpcRes.text();
	t.check(
		"XML-RPC rejects the same valid credentials",
		xmlrpcBody.includes("<fault>") || !xmlrpcEnabled,
		xmlrpcEnabled
			? xmlrpcBody.slice(0, 160).replaceAll("\n", " ")
			: "xmlrpc_enabled is false on this install",
	);
	t.check(
		"XML-RPC did not return a blog list",
		!xmlrpcBody.includes("<name>blogName</name>"),
		"a successful login would enumerate the site here",
	);

	// ---------------------------------------------------------------------
	// The passthroughs, which must survive
	// ---------------------------------------------------------------------
	//
	// A block that also breaks cron, WP-CLI, or the empty-form case is a different bug wearing the
	// fix's clothes. blockDirectAuth() is called directly here: these branches depend on ambient
	// state (a constant, a cron flag) that cannot be arranged through wp_authenticate() twice in one
	// process.

	const passthrough = await phpJson(
		server,
		`
		$sentinel = new WP_User(0);

		// Nothing submitted: hand back whatever core produced, since there is no credential to refuse
		// and core's "empty username" error is the better message.
		$empty = JwtAuth\\Validator::blockDirectAuth($sentinel, '', '');

		// Cron runs unattended and has no SSO flow available to it.
		add_filter('wp_doing_cron', '__return_true');
		$cron = JwtAuth\\Validator::blockDirectAuth($sentinel, 'someone', 'secret');
		remove_filter('wp_doing_cron', '__return_true');

		$stillBlocked = JwtAuth\\Validator::blockDirectAuth($sentinel, 'someone', 'secret');

		return [
			'empty_passes'  => $empty === $sentinel,
			'cron_passes'   => $cron === $sentinel,
			'normal_blocks' => is_wp_error($stillBlocked),
		];
		`,
	);
	t.check("an empty submission is left to core", passthrough.empty_passes);
	t.check("cron is not blocked", passthrough.cron_passes);
	t.check(
		"and an ordinary request is still blocked either side of that",
		passthrough.normal_blocks,
		"proves the two passthroughs above are conditional, not the default",
	);
} finally {
	await server[Symbol.asyncDispose]();
}

console.log(t.failures ? `\n${t.failures} failure(s)\n` : "\nAll checks passed\n");
process.exit(t.failures ? 1 : 0);
