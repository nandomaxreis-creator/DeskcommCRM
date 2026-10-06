/**
 * GET /sso/automultas?t=TOKEN — o painel do AUTOMULTAS abre o CRM já logado
 * (iframe da aba "Atendimento").
 *
 * Só entra quem JÁ TEM conta nesta instalação E é membro da organização do
 * escritório do token: o dono nasce no provisionamento
 * (`/api/v1/tenants/provision`) e a equipe é convidada pela tela "Equipe".
 * O token nunca cria usuário.
 *
 * A sessão sai de um link mágico gerado e consumido aqui mesmo no servidor —
 * nenhum e-mail é enviado. O mesmo `verifyOtp` de `app/auth/confirm/route.ts`.
 */
import { Redis } from "@upstash/redis";
import { NextResponse, type NextRequest } from "next/server";

import { slugDoProvisionamento } from "@/lib/auth/provision";
import { conferirTokenSso } from "@/lib/automultas/sso-token";
import { env } from "@/lib/env";
import { logger } from "@/lib/logger";
import { createAdminClient } from "@/lib/supabase/admin";
import { createClient } from "@/lib/supabase/server";

export const dynamic = "force-dynamic";

/** Id do usuário com exatamente este e-mail, ou null. (`filter` do GoTrue é substring.) */
async function idDaConta(email: string): Promise<string | null> {
  const url = `${env.NEXT_PUBLIC_SUPABASE_URL}/auth/v1/admin/users?filter=${encodeURIComponent(email)}`;
  const resp = await fetch(url, {
    headers: { apikey: env.SUPABASE_SERVICE_ROLE_KEY, Authorization: `Bearer ${env.SUPABASE_SERVICE_ROLE_KEY}` },
    cache: "no-store",
  });
  if (!resp.ok) return null;
  const corpo = (await resp.json()) as { users?: { id?: string; email?: string }[] };
  const achado = (corpo.users ?? []).find((u) => u.email?.toLowerCase() === email.toLowerCase());
  return achado?.id ?? null;
}

/**
 * O usuário é membro ativo da organização que o provisionamento criou para ESTE
 * escritório? No AUTOMULTAS o e-mail é único por empresa, não global: sem esta
 * conferência, um usuário de outra empresa com o mesmo e-mail entraria aqui.
 */
async function membroDoEscritorio(userId: string, idEmpresa: number): Promise<boolean> {
  const admin = createAdminClient();
  const { data: org } = await admin
    .from("organizations")
    .select("id")
    .eq("slug", slugDoProvisionamento("automultas", `empresa-${idEmpresa}`))
    .maybeSingle();
  if (!org) return false;
  const { data: vinculo } = await admin
    .from("user_organizations")
    .select("user_id")
    .eq("organization_id", org.id)
    .eq("user_id", userId)
    .is("revoked_at", null)
    .maybeSingle();
  return Boolean(vinculo);
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

  const userId = await idDaConta(dados.email);
  if (!userId) return negar("sem_conta");
  if (!(await membroDoEscritorio(userId, dados.id_empresa))) return negar("outro_escritorio");

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
