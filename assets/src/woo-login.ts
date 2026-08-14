// Bundle entry. Reads the server-provided config off `window` and starts the fallback injector.
//
// Kept separate from sso-button.ts so the logic can be imported by a test without a module-load
// side effect: importing this file installs a MutationObserver, importing that one does not.

import { install, readConfig } from "./sso-button";

const config = readConfig(window);
if (config) {
	install(window, config);
}
