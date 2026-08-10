"use client";

/**
 * Layout for every authenticated page.
 *
 * The `(app)` route group exists so /login and /register can sit outside it —
 * they need no shell, no guard, and no asset drawer.
 */

import { AppShell } from "@/components/app/AppShell";
import { AssetDrawerProvider } from "@/components/app/AssetDrawer";
import { AuthGuard } from "@/components/app/AuthGuard";

export default function AppLayout({ children }: { children: React.ReactNode }) {
  return (
    <AuthGuard>
      {/*
        The drawer provider wraps the shell rather than the page, so the drawer
        survives navigation between pages and every page shares one instance.
      */}
      <AssetDrawerProvider>
        <AppShell>{children}</AppShell>
      </AssetDrawerProvider>
    </AuthGuard>
  );
}
