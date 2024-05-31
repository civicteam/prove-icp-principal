import * as wasm from "./sig_verifier_js_bg.wasm";
import { __wbg_set_wasm } from "./sig_verifier_js_bg.js";
__wbg_set_wasm(wasm);
export * from "./sig_verifier_js_bg.js";
