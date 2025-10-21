import { z } from "zod";
export default class Validation {
  static createUserSchema = z.object({
    userName: z
      .string()
      .min(3, { message: "Username must be at least 3 characters long." }),

    email: z
      .string()
      .nonempty({ message: "Email is required." })
      .refine((val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val), {
        message: "Invalid email address.",
      }),
    password: z
      .string()
      .min(10, { message: "Password must be at least 10 characters long." }),
  });
  static loginSchema = z.object({
    email: z
      .string()
      .nonempty({ message: "Email is required." })
      .refine((val) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(val), {
        message: "Invalid email address.",
      }),
    password: z
      .string()
      .min(8, "Le mot de passe doit contenir au moins 8 caractères"),
    stay: z.boolean().optional().default(false),
  });
  static resetPasswordSchema = z.object({
    token: z.string().nonempty({ message: "Reset token is required." }),
    newPassword: z.string().min(10, {
      message: "New password must be at least 10 characters long.",
    }),
  });
  static forgetPasswordSchema = z.object({
    email: z.string().email("Email invalide"),
  });
}
