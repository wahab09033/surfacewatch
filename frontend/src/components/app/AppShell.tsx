"use client";

/**
 * The application shell: sidebar, top bar, and the surface pages render into.
 *
 * The sidebar collapses to icons only and remembers that choice in
 * localStorage. Below `sm` it becomes an overlay drawer instead, because a
 * 56px icon rail eats too much of a phone screen to be worth it.
 */

import Link from "next/link";
import { usePathname, useRouter } from "next/navigation";
import { useCallback, useEffect, useState } from "react";

import { cn } from "@/lib/format";
import { useLocalStorage } from "@/lib/hooks";

import { useAuth } from "../providers/AuthProvider";
import { useTheme } from "../providers/ThemeProvider";
import { ConfirmModal } from "../ui/Modal";
import {
  AssetsIcon,
  CollapseIcon,
  DashboardIcon,
  FindingsIcon,
  Logo,
  LogoutIcon,
  MenuIcon,
  MoonIcon,
  ReportsIcon,
  ScanIcon,
  ScheduleIcon,
  SettingsIcon,
  SunIcon,
} from "./icons";

const NAV = [
  { href: "/dashboard", label: "Dashboard", Icon: DashboardIcon },
  { href: "/assets", label: "Assets", Icon: AssetsIcon },
  { href: "/scan", label: "Scan", Icon: ScanIcon },
  { href: "/schedules", label: "Schedules", Icon: ScheduleIcon },
  { href: "/findings", label: "Findings", Icon: FindingsIcon },
  { href: "/reports", label: "Reports", Icon: ReportsIcon },
  { href: "/settings", label: "Settings", Icon: SettingsIcon },
] as const;

const SIDEBAR_KEY = "sw.sidebar.collapsed";

export function AppShell({ children }: { children: React.ReactNode }) {
  const [collapsed, setCollapsed] = useLocalStorage<boolean>(SIDEBAR_KEY, false);
  const [mobileOpen, setMobileOpen] = useState(false);
  const pathname = usePathname();

  // Close the mobile overlay on navigation, or it covers the page just opened.
  useEffect(() => {
    setMobileOpen(false);
  }, [pathname]);

  return (
    <div className="flex min-h-screen bg-bg">
      <Sidebar
        collapsed={collapsed}
        onToggleCollapse={() => setCollapsed(!collapsed)}
        mobileOpen={mobileOpen}
        onCloseMobile={() => setMobileOpen(false)}
      />

      <div className="flex min-w-0 flex-1 flex-col">
        <TopBar onOpenMobile={() => setMobileOpen(true)} />
        <main className="mx-auto w-full max-w-[1400px] flex-1 px-4 py-5 sm:px-6 sm:py-6">{children}</main>
      </div>
    </div>
  );
}

function Sidebar({
  collapsed,
  onToggleCollapse,
  mobileOpen,
  onCloseMobile,
}: {
  collapsed: boolean;
  onToggleCollapse: () => void;
  mobileOpen: boolean;
  onCloseMobile: () => void;
}) {
  const pathname = usePathname();
  const { organisation } = useAuth();

  return (
    <>
      {/* Mobile scrim. Hidden from the a11y tree; the close control is inside. */}
      {mobileOpen ? (
        <div
          className="fixed inset-0 z-40 bg-black/30 animate-fade-in sm:hidden dark:bg-black/55"
          onClick={onCloseMobile}
          aria-hidden="true"
        />
      ) : null}

      <aside
        className={cn(
          "z-50 flex shrink-0 flex-col border-r border-border bg-surface transition-[width] duration-150",
          // Mobile: fixed overlay that slides in. Desktop: static column.
          "fixed inset-y-0 left-0 sm:static",
          mobileOpen ? "flex" : "hidden sm:flex",
          collapsed ? "sm:w-14" : "sm:w-[216px]",
          "w-[240px]",
        )}
      >
        <div className={cn("flex h-14 items-center border-b border-border", collapsed ? "sm:justify-center sm:px-0" : "px-3.5")}>
          <Link
            href="/dashboard"
            className={cn("flex items-center gap-2.5 text-text", collapsed && "sm:gap-0")}
            title="SurfaceWatch"
          >
            <span className="text-accent">
              <Logo />
            </span>
            <span className={cn("text-sm font-semibold tracking-[-0.01em]", collapsed && "sm:hidden")}>
              SurfaceWatch
            </span>
          </Link>
        </div>

        <nav className="flex-1 overflow-y-auto p-2" aria-label="Main">
          <ul className="flex flex-col gap-0.5">
            {NAV.map(({ href, label, Icon }) => {
              // startsWith so /assets/123 keeps Assets lit, but guard the
              // boundary or /scan would also match /scanners.
              const active = pathname === href || pathname.startsWith(`${href}/`);
              return (
                <li key={href}>
                  <Link
                    href={href}
                    aria-current={active ? "page" : undefined}
                    title={collapsed ? label : undefined}
                    className={cn(
                      "flex h-8 items-center gap-2.5 rounded px-2 text-sm transition-colors",
                      collapsed && "sm:justify-center sm:px-0",
                      active ? "bg-bg font-medium text-text shadow-panel" : "text-muted hover:bg-bg/60 hover:text-text",
                    )}
                  >
                    <span className={cn("shrink-0", active && "text-accent")}>
                      <Icon />
                    </span>
                    <span className={cn("truncate", collapsed && "sm:hidden")}>{label}</span>
                  </Link>
                </li>
              );
            })}
          </ul>
        </nav>

        <div className="border-t border-border p-2">
          {organisation ? (
            <div className={cn("px-2 pb-2 pt-1", collapsed && "sm:hidden")}>
              <p className="truncate text-2xs uppercase tracking-wide text-muted">Organisation</p>
              <p className="truncate text-xs font-medium text-text" title={organisation.name}>
                {organisation.name}
              </p>
            </div>
          ) : null}

          <button
            type="button"
            onClick={onToggleCollapse}
            aria-label={collapsed ? "Expand sidebar" : "Collapse sidebar"}
            className={cn(
              "hidden h-8 w-full items-center gap-2.5 rounded px-2 text-sm text-muted transition-colors hover:bg-bg/60 hover:text-text sm:flex",
              collapsed && "sm:justify-center sm:px-0",
            )}
          >
            <span className={cn("shrink-0 transition-transform", collapsed && "rotate-180")}>
              <CollapseIcon />
            </span>
            <span className={cn(collapsed && "sm:hidden")}>Collapse</span>
          </button>

          <button
            type="button"
            onClick={onCloseMobile}
            className="flex h-8 w-full items-center gap-2.5 rounded px-2 text-sm text-muted transition-colors hover:bg-bg/60 hover:text-text sm:hidden"
          >
            Close menu
          </button>
        </div>
      </aside>
    </>
  );
}

function TopBar({ onOpenMobile }: { onOpenMobile: () => void }) {
  const { user, logout } = useAuth();
  const { resolved, toggle } = useTheme();
  const router = useRouter();
  const [confirmLogout, setConfirmLogout] = useState(false);

  const onLogout = useCallback(() => {
    setConfirmLogout(false);
    logout();
    router.replace("/login");
  }, [logout, router]);

  return (
    <header className="sticky top-0 z-30 flex h-14 shrink-0 items-center justify-between gap-3 border-b border-border bg-bg/85 px-4 backdrop-blur sm:px-6">
      <button
        type="button"
        onClick={onOpenMobile}
        aria-label="Open navigation"
        className="-ml-1 rounded p-1.5 text-muted transition-colors hover:bg-surface hover:text-text sm:hidden"
      >
        <MenuIcon />
      </button>

      <div className="flex flex-1 items-center justify-end gap-1.5">
        <button
          type="button"
          onClick={toggle}
          aria-label={resolved === "dark" ? "Switch to light theme" : "Switch to dark theme"}
          className="rounded p-1.5 text-muted transition-colors hover:bg-surface hover:text-text"
        >
          {resolved === "dark" ? <SunIcon /> : <MoonIcon />}
        </button>

        {user ? (
          <div className="flex items-center gap-2 border-l border-border pl-2">
            <div className="hidden text-right sm:block">
              <p className="max-w-[180px] truncate text-xs font-medium leading-tight text-text" title={user.email}>
                {user.full_name || user.email}
              </p>
              <p className="text-2xs capitalize leading-tight text-muted">{user.role}</p>
            </div>
            <button
              type="button"
              onClick={() => setConfirmLogout(true)}
              aria-label="Sign out"
              className="rounded p-1.5 text-muted transition-colors hover:bg-surface hover:text-text"
            >
              <LogoutIcon />
            </button>
          </div>
        ) : null}
      </div>

      <ConfirmModal
        open={confirmLogout}
        onClose={() => setConfirmLogout(false)}
        onConfirm={onLogout}
        title="Sign out?"
        description="You will need to sign in again to reach this organisation's data."
        confirmLabel="Sign out"
        destructive={false}
      />
    </header>
  );
}
