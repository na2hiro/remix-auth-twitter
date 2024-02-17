import type { Response } from "@remix-run/node";

export function isResponse(obj: unknown) {
  return obj && typeof obj === "object" && "status" in obj && "url" in obj;
}

export function assertResponse(obj: unknown): asserts obj is Response {
  if (!isResponse(obj)) throw new Error("Expected Response");
}
