import {
  Activity, BarChart3, Monitor, Bookmark, Clock, FileText, FileX, FolderOpen, Globe, HardDrive, Layers, LayoutDashboard, Link2, ListChecks, NotebookPen,
  Search, ShieldAlert, Usb, Users, Wrench, type LucideIcon,
} from 'lucide-react';
import type { CaseCounts } from '../lib/types';

export interface NavItem {
  to: string;
  label: string;
  icon: LucideIcon;
  /** Shown on the case desktop as a function tile. */
  description?: string;
  tone?: 'red' | 'green' | 'amber' | 'teal';
  count?: (c: CaseCounts) => number;
  countLabel?: (c: CaseCounts) => string;
  alert?: (c: CaseCounts) => boolean;
  permission?: string;
  /** Hidden from the case desktop tiles (still in the sidebar). */
  noTile?: boolean;
}

export interface NavGroup {
  title: string;
  items: NavItem[];
}

const n = (v: number) => v.toLocaleString();

export const NAV: NavGroup[] = [
  {
    title: 'Workspace',
    items: [
      { to: '/app', label: 'Case desktop', icon: LayoutDashboard, noTile: true },
      {
        to: '/app/dashboard', label: 'Activity dashboard', icon: BarChart3, tone: 'teal',
        description: 'When the computer was used, top websites, file types and USB connections, as charts.',
      },
    ],
  },
  {
    title: 'Case',
    items: [
      { to: '/app/cases', label: 'Cases', icon: FolderOpen, noTile: true },
      {
        to: '/app/evidence', label: 'Evidence', icon: HardDrive,
        description: 'Upload disk images, verify SHA-256 integrity and run the full analysis.',
        count: (c) => c.evidence, countLabel: (c) => `${n(c.evidence_analyzed)} of ${n(c.evidence)} analyzed`,
      },
    ],
  },
  {
    title: 'Analysis',
    items: [
      {
        to: '/app/files', label: 'Deleted files', icon: FileX, tone: 'red',
        description: 'Browse the Sleuth Kit file index and recover deleted files with icat.',
        count: (c) => c.deleted_files, countLabel: (c) => `${n(c.files)} files indexed · ${n(c.recovered_files)} recovered`,
      },
      {
        to: '/app/timeline', label: 'Timeline', icon: Clock,
        description: 'Filesystem MACB times, browser, USB and Windows activity in one chronology.',
        count: (c) => c.timeline_events, countLabel: () => 'events',
      },
      {
        to: '/app/browser', label: 'Browser history', icon: Globe, tone: 'teal',
        description: 'Visits and downloads from Chrome, Edge, Brave and Firefox.',
        count: (c) => c.browser_history + c.browser_downloads, countLabel: (c) => `${n(c.browser_history)} visits · ${n(c.browser_downloads)} downloads`,
      },
      {
        to: '/app/usb', label: 'USB devices', icon: Usb, tone: 'amber',
        description: 'Removable storage history from the SYSTEM hive and setupapi.dev.log.',
        count: (c) => c.usb_devices, countLabel: () => 'devices',
      },
      {
        to: '/app/activity', label: 'Windows activity', icon: Activity, tone: 'teal',
        description: 'Programs run (Prefetch), files opened (Recent shortcuts) and the Recycle Bin.',
        count: (c) => c.programs_run + c.recent_files + c.recycle_bin_items,
        countLabel: (c) => `${n(c.programs_run)} programs · ${n(c.recent_files)} opened · ${n(c.recycle_bin_items)} recycled`,
      },
      {
        to: '/app/computer', label: 'Computer and users', icon: Monitor, tone: 'teal',
        description: 'Computer name, Windows version, network, time zone and user accounts from the registry.',
        count: (c) => c.user_accounts ?? 0, countLabel: () => 'user accounts',
      },
      {
        to: '/app/indicators', label: 'Indicators', icon: ShieldAlert, tone: 'red',
        description: 'YARA matches, activity patterns and statistical anomalies.',
        count: (c) => c.malware_indicators + c.patterns, alert: (c) => c.malware_indicators > 0,
        countLabel: (c) => `${n(c.malware_indicators)} YARA · ${n(c.patterns)} patterns · ${n(c.anomalies_flagged)} anomalies`,
      },
      {
        to: '/app/carving', label: 'File carving', icon: Layers,
        description: 'Recover files from unallocated space with PhotoRec or Scalpel.',
        count: (c) => c.carved_files, countLabel: () => 'carved files',
      },
      {
        to: '/app/search', label: 'Keyword search', icon: Search,
        description: 'Search file paths, timeline, browser records, USB devices, Windows activity and findings.',
      },
    ],
  },
  {
    title: 'Reporting',
    items: [
      {
        to: '/app/findings', label: 'Findings', icon: NotebookPen, tone: 'amber',
        description: 'Record investigator observations linked to evidence.',
        count: (c) => c.findings, countLabel: () => 'findings',
      },
      {
        to: '/app/tagged', label: 'Tagged items', icon: Bookmark, tone: 'red',
        description: 'Files, events, visits, devices and activity bookmarked during review, with notes.',
        count: (c) => c.tags, countLabel: () => 'tagged items',
      },
      {
        to: '/app/reports', label: 'Reports', icon: FileText, tone: 'green',
        description: 'Generate versioned, hash-sealed PDF investigation reports.',
        count: (c) => c.reports, countLabel: () => 'reports',
      },
      {
        to: '/app/custody', label: 'Chain of custody', icon: Link2, tone: 'green',
        description: 'Every registration, integrity check and recovery, in order.',
        count: (c) => c.custody_events, countLabel: () => 'custody records',
      },
    ],
  },
  {
    title: 'Administration',
    items: [
      { to: '/app/admin/users', label: 'Users', icon: Users, permission: 'USER_MANAGE', noTile: true },
      { to: '/app/admin/audit', label: 'Audit log', icon: ListChecks, permission: 'AUDIT_READ', noTile: true },
      { to: '/app/admin/system', label: 'System & tools', icon: Wrench, noTile: true },
    ],
  },
];
