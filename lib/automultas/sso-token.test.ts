import { createHmac } from "node:crypto";
import { describe, expect, it } from "vitest";

import { conferirTokenSso } from "./sso-token";

const SEGREDO = "x".repeat(64);
const b64 = (s: string | Buffer) => Buffer.from(s).toString("base64url");
function gerar(payload: object, segredo = SEGREDO) {
  const json = JSON.stringify(payload);
  return `${b64(json)}.${b64(createHmac("sha256", segredo).update(json).digest())}`;
}
const agora = 1_000_000;
const valido = { email: "a@b.com", id_empresa: 7, exp: agora + 60, jti: "a".repeat(32) };

describe("conferirTokenSso", () => {
  it("aceita token íntegro e no prazo", () => {
    expect(conferirTokenSso(gerar(valido), SEGREDO, agora)).toEqual(valido);
  });
  it("recusa assinatura de outro segredo", () => {
    expect(conferirTokenSso(gerar(valido, "y".repeat(64)), SEGREDO, agora)).toBeNull();
  });
  it("recusa corpo adulterado com a assinatura original", () => {
    const [, assinatura] = gerar(valido).split(".");
    const outro = b64(JSON.stringify({ ...valido, email: "intruso@b.com" }));
    expect(conferirTokenSso(`${outro}.${assinatura}`, SEGREDO, agora)).toBeNull();
  });
  it("recusa vencido", () => {
    expect(conferirTokenSso(gerar({ ...valido, exp: agora - 1 }), SEGREDO, agora)).toBeNull();
  });
  it("recusa prazo longo demais (> 120 s)", () => {
    expect(conferirTokenSso(gerar({ ...valido, exp: agora + 3600 }), SEGREDO, agora)).toBeNull();
  });
  it("recusa lixo, campo a mais e segredo curto", () => {
    expect(conferirTokenSso("abc", SEGREDO, agora)).toBeNull();
    expect(conferirTokenSso(gerar({ ...valido, role: "admin" }), SEGREDO, agora)).toBeNull();
    expect(conferirTokenSso(gerar(valido, "curto"), "curto", agora)).toBeNull();
  });
});
