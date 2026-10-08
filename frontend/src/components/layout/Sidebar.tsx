"use client";

import Link from "next/link";
import { usePathname } from "next/navigation";
import { cn } from "@/lib/cn";

const NAV_SECTIONS = [
  {
    items: [{ href: "/dashboard", label: "Dashboard" }],
  },
  {
    heading: "Triage",
    items: [
      { href: "/alerts", label: "Alerts" },
      { href: "/incidents", label: "Incidents" },
      { href: "/events", label: "Events" },
    ],
  },
  {
    heading: "Intelligence",
    items: [
      { href: "/detections", label: "Detection Rules" },
      { href: "/threat-intel", label: "Threat Intel" },
      { href: "/attack", label: "ATT&CK Coverage" },
      { href: "/knowledge", label: "Knowledge Base" },
    ],
  },
  {
    heading: "Investigate",
    items: [{ href: "/copilot", label: "AI Copilot" }],
  },
];

export function Sidebar() {
  const pathname = usePathname();

  return (
    <nav className="flex h-full w-56 flex-col border-r border-border bg-panel" aria-label="Main navigation">
      <div className="flex h-14 items-center gap-2 border-b border-border px-4">
        <span className="h-2 w-2 rounded-full bg-accent" aria-hidden="true" />
        <span className="font-semibold tracking-tight text-ink">SentinelForge</span>
      </div>

      <div className="flex-1 overflow-y-auto px-2 py-4">
        {NAV_SECTIONS.map((section, i) => (
          <div key={i} className={i > 0 ? "mt-5" : ""}>
            {section.heading && (
              <div className="px-2 pb-1.5 text-[11px] font-medium text-ink-faint">{section.heading}</div>
            )}
            <ul className="space-y-0.5">
              {section.items.map((item) => {
                const active = pathname === item.href || pathname?.startsWith(`${item.href}/`);
                return (
                  <li key={item.href}>
                    <Link
                      href={item.href}
                      aria-current={active ? "page" : undefined}
                      className={cn(
                        "block rounded px-2 py-1.5 text-sm transition-colors",
                        active
                          ? "bg-elevated text-ink font-medium"
                          : "text-ink-muted hover:bg-elevated/60 hover:text-ink",
                      )}
                    >
                      {item.label}
                    </Link>
                  </li>
                );
              })}
            </ul>
          </div>
        ))}
      </div>
    </nav>
  );
}
