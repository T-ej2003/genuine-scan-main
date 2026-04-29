import { z } from "zod";

export const manufacturerInviteSchema = z.object({
  licenseeId: z.string().min(1, "Choose a brand."),
  name: z.string().trim().min(2, "Enter the manufacturer name."),
  email: z.string().trim().email("Enter a valid email address."),
  location: z.string().trim().optional().default(""),
  website: z
    .string()
    .trim()
    .optional()
    .default("")
    .refine((value) => !value || /^https?:\/\//i.test(value), "Website must start with http:// or https://"),
});

export type ManufacturerInviteFormValues = z.infer<typeof manufacturerInviteSchema>;
