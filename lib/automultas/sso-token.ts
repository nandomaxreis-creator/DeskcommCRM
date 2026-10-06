/**
 * Token de SSO que o AUTOMULTAS (multas.holyfs.com.br) gera para abrir o CRM
 * já logado dentro do iframe do painel dele.
 *
 * Formato: `base64url(json) + "." + base64url(hmac_sha256(json, segredo))`,
 * com json `{ email, id_empresa, exp, jti }`. O PHP gera igual
 * (`includes/crm.php::crm_token_sso`). Uso único (`jti`) é cobrado na rota.
 */
import { createHmac, timingSafeEqual } from "node:crypto";
import { z } from "zod";

const payloadSchema = z
  .object({
    email: z.string().email(),
    id_empresa: z.number().int().positive(),
    exp: z.number().int(),
    jti: z.string().regex(/^[a-f0-9]{32}$/),
  })
  .strict();
export type TokenSso = z.infer<typeof payloadSchema>;

/** O AUTOMULTAS emite com 60 s; acima de 120 s é token que não saiu de lá. */
const PRAZO_MAXIMO_S = 120;

/** Devolve o payload se a assinatura confere e o prazo vale; senão `null`. */
export function conferirTokenSso(
  token: string,
  segredo: string,
  agoraS = Math.floor(Date.now() / 1000),
): TokenSso | null {
  if (segredo.length < 32) return null;
  const [corpo, assinatura, ...resto] = token.split(".");
  if (!corpo || !assinatura || resto.length) return null;
  const json = Buffer.from(corpo, "base64url").toString("utf8");
  const esperada = createHmac("sha256", segredo).update(json).digest();
  const recebida = Buffer.from(assinatura, "base64url");
  if (recebida.length !== esperada.length || !timingSafeEqual(recebida, esperada)) return null;
  let dados: unknown;
  try {
    dados = JSON.parse(json);
  } catch {
    return null;
  }
  const p = payloadSchema.safeParse(dados);
  if (!p.success) return null;
  if (p.data.exp < agoraS || p.data.exp > agoraS + PRAZO_MAXIMO_S) return null;
  return p.data;
}
