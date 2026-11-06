export function isValidTokenFormat(token: string): boolean {
  return typeof token === "string" && /^[a-f0-9]{64}$/.test(token);
}