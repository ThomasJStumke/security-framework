import { createClient } from "@supabase/supabase-js";

// BUG: this file has no .server.ts suffix, so it can ship to the browser bundle.
export const adminClient = createClient(
  import.meta.env.VITE_SUPABASE_URL,
  import.meta.env.SUPABASE_SERVICE_ROLE_KEY,
);
