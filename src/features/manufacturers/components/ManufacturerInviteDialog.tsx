import { useEffect } from "react";
import { zodResolver } from "@hookform/resolvers/zod";
import { useForm } from "react-hook-form";

import { Button } from "@/components/ui/button";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Form, FormControl, FormField, FormItem, FormLabel, FormMessage } from "@/components/ui/form";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";

import { manufacturerInviteSchema, type ManufacturerInviteFormValues } from "@/features/manufacturers/schemas";
import type { LicenseeOption } from "@/features/manufacturers/types";

type ManufacturerInviteDialogProps = {
  open: boolean;
  onOpenChange: (open: boolean) => void;
  isSuperAdmin: boolean;
  licensees: LicenseeOption[];
  defaultLicenseeId?: string;
  submitting: boolean;
  onSubmit: (values: ManufacturerInviteFormValues) => Promise<void>;
};

const buildDefaults = (defaultLicenseeId?: string): ManufacturerInviteFormValues => ({
  licenseeId: defaultLicenseeId || "",
  name: "",
  email: "",
  location: "",
  website: "",
});

export function ManufacturerInviteDialog({
  open,
  onOpenChange,
  isSuperAdmin,
  licensees,
  defaultLicenseeId,
  submitting,
  onSubmit,
}: ManufacturerInviteDialogProps) {
  const form = useForm<ManufacturerInviteFormValues>({
    resolver: zodResolver(manufacturerInviteSchema),
    defaultValues: buildDefaults(defaultLicenseeId),
  });

  useEffect(() => {
    if (!open) return;
    form.reset(buildDefaults(defaultLicenseeId));
  }, [defaultLicenseeId, form, open]);

  return (
    <Dialog open={open} onOpenChange={onOpenChange}>
      <DialogContent className="sm:max-w-[560px]">
        <DialogHeader>
          <DialogTitle>Invite manufacturer</DialogTitle>
          <DialogDescription>
            Add a manufacturer admin with a one-time activation link and printer setup access.
          </DialogDescription>
        </DialogHeader>

        <Form {...form}>
          <form className="space-y-4" onSubmit={form.handleSubmit((values) => void onSubmit(values))}>
            {isSuperAdmin ? (
              <FormField
                control={form.control}
                name="licenseeId"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Licensee</FormLabel>
                    <Select value={field.value} onValueChange={field.onChange}>
                      <FormControl>
                        <SelectTrigger>
                          <SelectValue placeholder="Choose a licensee" />
                        </SelectTrigger>
                      </FormControl>
                      <SelectContent>
                        {licensees.map((licensee) => (
                          <SelectItem key={licensee.id} value={licensee.id}>
                            {licensee.name} ({licensee.prefix})
                          </SelectItem>
                        ))}
                      </SelectContent>
                    </Select>
                    <FormMessage />
                  </FormItem>
                )}
              />
            ) : null}

            <div className="grid gap-4 sm:grid-cols-2">
              <FormField
                control={form.control}
                name="name"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Manufacturer name</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="Factory A" disabled={submitting} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="email"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Admin email</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="factory@example.com" disabled={submitting} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            <div className="rounded-xl border border-emerald-200 bg-emerald-50 p-3 text-sm text-emerald-900">
              The invite email includes the activation link and connector download page. It expires after 24 hours.
            </div>

            <div className="grid gap-4 sm:grid-cols-2">
              <FormField
                control={form.control}
                name="location"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Location</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="City, Country" disabled={submitting} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />

              <FormField
                control={form.control}
                name="website"
                render={({ field }) => (
                  <FormItem>
                    <FormLabel>Website</FormLabel>
                    <FormControl>
                      <Input {...field} placeholder="https://factory.example" disabled={submitting} />
                    </FormControl>
                    <FormMessage />
                  </FormItem>
                )}
              />
            </div>

            {!isSuperAdmin ? (
              <div className="space-y-1 rounded-xl border bg-muted/30 p-3 text-sm text-muted-foreground">
                <Label className="text-xs uppercase tracking-[0.16em] text-muted-foreground">Role</Label>
                <div className="font-medium text-foreground">Manufacturer Admin</div>
              </div>
            ) : null}

            <div className="flex justify-end gap-2">
              <Button type="button" variant="outline" onClick={() => onOpenChange(false)} disabled={submitting}>
                Cancel
              </Button>
              <Button type="submit" disabled={submitting}>
                {submitting ? "Sending invite..." : "Send invite"}
              </Button>
            </div>
          </form>
        </Form>
      </DialogContent>
    </Dialog>
  );
}
