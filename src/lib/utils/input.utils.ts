import { ZodError } from "zod";
import { UserRegisterInput } from "../../validation/register.validation";
import { z } from 'zod';

type FlatError = Partial<Record<keyof UserRegisterInput, string[]>>;

export function toFieldsErrors(error: ZodError) {
  const flat = z.flattenError(error).fieldErrors as FlatError;
  return {
    name: flat?.name?.[0],
    email: flat?.email?.[0],
    password: flat?.password?.[0],
  };
}

export function validateEmail(value: string): void {
  if (
    typeof value !== "string" ||
    !/^[^\s@<>,;"]+@[^\s@<>,;"]+\.[^\s@<>,;"]+$/.test(value)
  ) {
    throw new Error("Invalid email address");
  }
}

export function requireEnv(name: string): string {
  const value = process.env[name];
  if (!value?.trim()) {
    throw new Error(`Missing environment variable: ${name}`);
  }
  return value;
}