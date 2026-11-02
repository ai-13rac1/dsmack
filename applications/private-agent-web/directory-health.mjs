#!/usr/bin/env -S deno run --allow-net --allow-read --allow-write --allow-run
// Run the page's directory checks and notify only when outage state changes.
import { discoverChainNodes } from "./chain-directory.mjs";

export async function checkDirectory(url, { fetcher = fetch } = {}) {
  const response = await fetcher(url, { redirect: "error", signal: AbortSignal.timeout(15000) });
  if (!response.ok) throw Error(`config.json HTTP ${response.status}`);
  const config = await response.json();
  const directory = await discoverChainNodes({ config, fetcher });
  if (!directory.nodes.length) throw Error("No signed guest entries");
  return { nodes: directory.nodes.length, blockNumber: directory.blockNumber, blockHash: directory.blockHash };
}

export async function monitor({ target, url, state, notify, check = checkDirectory }) {
  let prior = null;
  try { prior = JSON.parse(await Deno.readTextFile(state)); }
  catch (error) { if (!(error instanceof Deno.errors.NotFound)) throw error; }
  let result;
  try { result = { ok: true, ...await check(url) }; }
  catch (error) { result = { ok: false, error: error.message }; }
  if ((!result.ok && prior?.ok !== false) || (result.ok && prior?.ok === false)) {
    const message = `Dsmack ${target} directory ${result.ok ? "RECOVERED" : "FAILED"}: ${url}\n${result.ok ? `${result.nodes} signed guest(s), block ${result.blockNumber}` : result.error}`;
    await notify(message);
    result.notification = result.ok ? "recovery" : "failure";
  }
  await Deno.writeTextFile(state + ".tmp", JSON.stringify({ ...result, checkedAt: new Date().toISOString() }) + "\n", { mode: 0o600 });
  await Deno.rename(state + ".tmp", state);
  console.log(JSON.stringify({ target, url, ...result }));
  return result;
}

if (import.meta.main) {
  const [target, url, state, notifier] = Deno.args;
  if (!notifier) throw Error("usage: directory-health.mjs TARGET CONFIG_URL STATE_FILE NOTIFY_SCRIPT");
  const result = await monitor({ target, url, state, notify: async message => {
    const child = new Deno.Command(notifier, { args: [message], stdout: "null", stderr: "inherit" }).spawn();
    const status = await child.status;
    if (!status.success) throw Error(`Notification failed with exit ${status.code}; outage state retained`);
  } });
  if (!result.ok) Deno.exit(1);
}
