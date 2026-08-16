import { createFileRoute } from "@tanstack/react-router";

// BUG: lives under src/routes/api/ like a real server route, but the service-role
// reference is NOT inside the framework's server-handlers wrapper object -- e.g. a
// top-level export any client module in this file could import. The exemption for
// TanStack Start's server-route pattern must be structural (provably server-only),
// not just "anything under routes/api/", so this must still be flagged.
export const dangerousAdminKey = process.env.SUPABASE_SERVICE_ROLE_KEY;

export const Route = createFileRoute("/api/leaky-not-wrapped")({});
