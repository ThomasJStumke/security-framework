import { createFileRoute } from "@tanstack/react-router";
import { createPlatformSupabase } from "@/lib/supabase-admin.server";

// OK: real-world false-positive case (Mission Control's src/routes/api/security/events.ts,
// 2026-08-16). This entire route's logic is wrapped in TanStack Start's `server: { handlers }`
// boundary, which the framework compiles into server-only output -- never bundled client-side,
// verified by grepping the built .output/public/**/*.js for zero trace of this file's imports.
// The literal string "service_role" below is a denylist regex fragment used to REJECT payloads
// containing that pattern, not a credential reference -- doubly a false positive.
const FORBIDDEN_VALUE_PATTERNS = [/service_role/i];

export const Route = createFileRoute("/api/security/events")({
  server: {
    handlers: {
      POST: async () => {
        const db = createPlatformSupabase();
        return db.from("mc_security_events").select("*");
      },
    },
  },
});
