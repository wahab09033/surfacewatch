import type { Metadata, Viewport } from "next";

import { AuthProvider } from "@/components/providers/AuthProvider";
import { ThemeProvider } from "@/components/providers/ThemeProvider";
import { ToastProvider } from "@/components/providers/ToastProvider";

import "./globals.css";

export const metadata: Metadata = {
  title: "SurfaceWatch",
  description: "Attack surface management for security teams.",
  // This is an authenticated console; there is nothing here worth indexing and
  // a good deal worth not indexing.
  robots: { index: false, follow: false },
};

export const viewport: Viewport = {
  width: "device-width",
  initialScale: 1,
  // Matches the page background in both themes so the mobile browser chrome
  // does not flash white over a dark page.
  themeColor: [
    { media: "(prefers-color-scheme: light)", color: "#ffffff" },
    { media: "(prefers-color-scheme: dark)", color: "#111113" },
  ],
};

/**
 * Applies the stored theme before first paint.
 *
 * Without this the page renders light, then swaps to dark once React hydrates —
 * a full-screen flash on every load for anyone using the dark theme. It has to
 * be inline and synchronous in <head> to land ahead of the first paint.
 */
const THEME_SCRIPT = `
(function() {
  try {
    var stored = localStorage.getItem('sw.theme');
    var dark = stored === 'dark' ||
      ((!stored || stored === 'system') &&
        window.matchMedia('(prefers-color-scheme: dark)').matches);
    if (dark) {
      document.documentElement.classList.add('dark');
      document.documentElement.style.colorScheme = 'dark';
    } else {
      document.documentElement.style.colorScheme = 'light';
    }
  } catch (e) {}
})();
`;

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en" suppressHydrationWarning>
      <head>
        <script dangerouslySetInnerHTML={{ __html: THEME_SCRIPT }} />
      </head>
      <body className="bg-bg text-text antialiased">
        <ThemeProvider>
          <ToastProvider>
            <AuthProvider>{children}</AuthProvider>
          </ToastProvider>
        </ThemeProvider>
      </body>
    </html>
  );
}
