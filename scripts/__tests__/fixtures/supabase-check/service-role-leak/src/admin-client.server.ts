import { createClient } from "@supabase/supabase-js";

// OK: *.server.ts never bundles into client JS.
export const adminClient = createClient(process.env.SUPABASE_URL!, process.env.SUPABASE_SERVICE_ROLE_KEY!);
