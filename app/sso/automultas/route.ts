/**
 * GET /sso/automultas?t=TOKEN — o painel do AUTOMULTAS abre o CRM já logado
 * (iframe da aba "Atendimento").
 *
 * Só entra quem JÁ TEM conta nesta instalação: o dono nasce no
 * provisionamento (`/api/v1/tenants/provision`) e a equipe é convidada pela
 * tela "Equipe". O token nunca cria usuário.
 *
 * A sessão sai de um link mágico gerado e consumido aqui mesmo no servidor —
 * nenhum e-mail é enviado. O mesmo `verifyOtp` de `app/auth/confirm/route.ts`.
 */
import { Redis } from "@upstash/redis";
import { NextResponse, type NextRequest } from "next/server";

import { conferirTokenSso } from "@/lib/automultas/sso-token";
import { env } from "@/lib/env";
import { logger } from "@/lib/logger";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

/** Existe usuário com exatamente este e-mail? (`filter` do GoTrue é substring.) */
async function contaExiste(email: string): Promise<boolean> {
  const url = `${env.NEXT_PUBLIC_SUPABASE_URL}/auth/v1/admin/users?filter=${encodeURIComponent(email)}`;
  const resp = await fetch(url, {
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}` },
    cache: "no-store",
  });
  if (!resp.ok) return false;
  const corpo = (await resp.json()) as { users?: { email?: string }[] };
  return (corpo.users ?? []).some((u) => u.email?.toLowerCase() === email.toLowerCase());
}

export async function GET(req: NextRequest) {
  const negar = (motivo: string) => {
    logger.warn("[sso.automultas] recusado", { motivo });
    return NextResponse.redirect(new URL("/login?error=sso_invalido", env.NEXT_PUBLIC_APP_URL), 303);
  };

  const dados = conferirTokenSso(req.nextUrl.searchParams.get("t") ?? "", env.AUTOMULTAS_SSO_SECRET);
  if (!dados) return negar("token");

  // Uso único. Sem Redis, recusa: aceitar sem conferir reuso abriria replay.
  try {
    const redis = new Redis({ url: env.UPSTASH_REDIS_REST_URL, token: env.UPSTASH_REDIS_REST_TOKEN, retry: false });
    const primeiro = await redis.set(`sso:automultas:jti:${dados.jti}`, 1, { nx: true, ex: 300 });
    if (primeiro !== "OK") return negar("reuso");
  } catch (err) {
    logger.error("[sso.automultas] redis indisponível", { erro: err instanceof Error ? err.message : String(err) });
    return negar("redis");
  }

  if (!(await contaExiste(dados.email))) return negar("sem_conta");

  const { data: link, error } = await createAdminClient().auth.admin.generateLink({
    type: "magiclink",
    email: dados.email,
  });
  if (error || !link?.properties?.hashed_token) return negar("link");

  const supabase = await createClient();
  const { error: e2 } = await supabase.auth.verifyOtp({ type: "magiclink", token_hash: link.properties.hashed_token });
  if (e2) return negar("otp");

  return NextResponse.redirect(new URL("/app", env.NEXT_PUBLIC_APP_URL), 303);
}
