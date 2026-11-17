// Agent Shompa · file vault (Supabase Edge Function "shompa-files")
//
// Holds the Cloudflare R2 keys so the apps never see them. A signed-in app asks this
// function for a short-lived link, then uploads to / downloads from R2 directly.
//
// Secrets to set in Supabase → Edge Functions → Secrets:
//   R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_ENDPOINT (https://<account>.r2.cloudflarestorage.com), R2_BUCKET (shompa-files)
//
// Request (POST, JSON, with the user's "Authorization: Bearer <token>" and "apikey" headers):
//   { "action": "upload",   "folder": "lab_report", "fileName": "report.pdf" } → { key, url }   (PUT the file to url)
//   { "action": "download", "key": "<key>" }                                    → { url }        (GET within 10 minutes)
//   { "action": "delete",   "key": "<key>" }                                    → { ok: true }
//   { "action": "ping" }                                                        → { ok, user, bucket }

import { AwsClient } from "npm:aws4fetch@1.0.20";

const CORS = {
  "Access-Control-Allow-Origin": "*",
  "Access-Control-Allow-Headers": "authorization, apikey, content-type, x-client-info",
  "Access-Control-Allow-Methods": "POST, OPTIONS",
};
const FOLDERS = ["dev_swatch", "lab_report", "fastness", "problem_photo", "other", "migrated"];
const UPLOAD_SECONDS = 600;   // upload link lives 10 minutes
const DOWNLOAD_SECONDS = 600; // view link lives 10 minutes

const json = (body: unknown, status = 200) =>
  new Response(JSON.stringify(body), { status, headers: { ...CORS, "Content-Type": "application/json" } });

function env(name: string): string {
  const v = Deno.env.get(name);
  if (!v) throw new Error(`Missing secret ${name}. Add it in Supabase → Edge Functions → Secrets.`);
  return v;
}

/** Asks Supabase Auth who owns this token. Returns the user id or null. */
async function userId(req: Request): Promise<string | null> {
  const auth = req.headers.get("authorization") ?? "";
  const apikey = req.headers.get("apikey") ?? Deno.env.get("SUPABASE_ANON_KEY") ?? "";
  if (!auth.startsWith("Bearer ")) return null;
  const r = await fetch(`${env("SUPABASE_URL")}/auth/v1/user`, { headers: { Authorization: auth, apikey } });
  if (!r.ok) return null;
  const u = await r.json();
  return typeof u?.id === "string" ? u.id : null;
}

/** Keeps letters, digits, dot, dash and underscore; never empty; max 120 chars. */
function safeName(n: string): string {
  const base = n.normalize("NFKD").replace(/[^\w.\-]+/g, "_").replace(/_+/g, "_").replace(/^[._]+/, "");
  return (base || "file").slice(-120);
}

function objectUrl(key: string): URL {
  const endpoint = env("R2_ENDPOINT").replace(/\/+$/, "");
  return new URL(`${endpoint}/${env("R2_BUCKET")}/${key.split("/").map(encodeURIComponent).join("/")}`);
}

async function presign(key: string, method: "PUT" | "GET", seconds: number): Promise<string> {
  const r2 = new AwsClient({
    accessKeyId: env("R2_ACCESS_KEY_ID"),
    secretAccessKey: env("R2_SECRET_ACCESS_KEY"),
    service: "s3",
    region: "auto",
  });
  const url = objectUrl(key);
  url.searchParams.set("X-Amz-Expires", String(seconds));
  const signed = await r2.sign(new Request(url, { method }), { aws: { signQuery: true } });
  return signed.url;
}

async function remove(key: string): Promise<void> {
  const r2 = new AwsClient({
    accessKeyId: env("R2_ACCESS_KEY_ID"),
    secretAccessKey: env("R2_SECRET_ACCESS_KEY"),
    service: "s3",
    region: "auto",
  });
  const r = await r2.fetch(objectUrl(key).toString(), { method: "DELETE" });
  if (!r.ok && r.status !== 404) throw new Error(`R2 delete failed (${r.status})`);
}

Deno.serve(async (req) => {
  if (req.method === "OPTIONS") return new Response("ok", { headers: CORS });
  if (req.method !== "POST") return json({ error: "Use POST." }, 405);
  try {
    const uid = await userId(req);
    if (!uid) return json({ error: "Please sign in again." }, 401);

    const body = await req.json().catch(() => ({}));
    const action = String(body.action ?? "");
    // A key always starts with the user's own id, so nobody can reach someone else's files.
    const ownKey = (k: unknown) => typeof k === "string" && k.startsWith(`${uid}/`) && !k.includes("..");

    if (action === "ping") return json({ ok: true, user: uid, bucket: env("R2_BUCKET") });

    if (action === "upload") {
      const folder = FOLDERS.includes(body.folder) ? body.folder : "other";
      const stamp = new Date().toISOString().replace(/[-:T]/g, "").slice(0, 14);
      const rand = crypto.randomUUID().slice(0, 8);
      const key = `${uid}/${folder}/${stamp}_${rand}_${safeName(String(body.fileName ?? "file"))}`;
      return json({ key, url: await presign(key, "PUT", UPLOAD_SECONDS) });
    }
    if (action === "download") {
      if (!ownKey(body.key)) return json({ error: "File not found." }, 404);
      return json({ url: await presign(body.key, "GET", DOWNLOAD_SECONDS) });
    }
    if (action === "delete") {
      if (!ownKey(body.key)) return json({ error: "File not found." }, 404);
      await remove(body.key);
      return json({ ok: true });
    }
    return json({ error: "Unknown action." }, 400);
  } catch (e) {
    return json({ error: e instanceof Error ? e.message : String(e) }, 500);
  }
});
