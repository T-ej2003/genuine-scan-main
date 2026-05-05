import { useTheme } from "next-themes";
import { Moon, Sun } from "lucide-react";

import { Button } from "@/components/ui/button";
import { useToast } from "@/hooks/use-toast";
import { hasConsent } from "@/lib/consent";

export function DashboardThemeToggle() {
  const { toast } = useToast();
  const { resolvedTheme, setTheme } = useTheme();

  const toggleTheme = () => {
    if (!hasConsent("functional")) {
      toast({
        title: "Preference storage disabled",
        description: "Theme changes can be saved after functional cookies are enabled.",
      });
      return;
    }
    setTheme(resolvedTheme === "dark" ? "light" : "dark");
  };

  return (
    <Button
      type="button"
      variant="ghost"
      size="icon"
      onClick={toggleTheme}
      aria-label={`Switch to ${resolvedTheme === "dark" ? "light" : "dark"} theme`}
      className="hidden sm:inline-flex"
    >
      {resolvedTheme === "dark" ? <Sun className="h-4 w-4" /> : <Moon className="h-4 w-4" />}
    </Button>
  );
}
