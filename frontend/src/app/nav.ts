import {
  Activity, BarChart3, Monitor, Bookmark, Clock, FileClock, FileText, FileX, Fingerprint, FolderOpen, Globe, HardDrive, Layers, LayoutDashboard, Link2, ListChecks, NotebookPen, ScanSearch,
  ScrollText, Search, ShieldAlert, Usb, Users, Wrench, type LucideIcon,
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
        to: '/app/files', label: 'Files', icon: FileX, tone: 'red',
        description: 'Every file with its hashes and real type, renamed and encrypted files, and deleted files recovered with icat.',
        count: (c) => c.files,
        countLabel: (c) => `${n(c.deleted_files)} deleted · ${n(c.recovered_files)} recovered · ${n((c.renamed_files ?? 0) + (c.encrypted_files ?? 0))} renamed or encrypted`,
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
        description: 'Removable storage history from the SYSTEM hive, setupapi.dev.log and the event logs.',
        count: (c) => c.usb_devices, countLabel: () => 'devices',
      },
      {
        to: '/app/activity', label: 'Windows activity', icon: Activity, tone: 'teal',
        description: 'Programs run, files opened, the Recycle Bin, folders browsed, searches, autostart entries, installed programs, Jump Lists, the Windows Timeline, thumbnails, SRUM and the search index.',
        count: (c) => c.programs_run + c.recent_files + c.recycle_bin_items + (c.programs_executed ?? 0) + (c.folders_browsed ?? 0),
        alert: (c) => (c.persistence_flagged ?? 0) > 0,
        countLabel: (c) => `${n(c.programs_run)} Prefetch · ${n(c.folders_browsed ?? 0)} folders · ${n(c.persistence_flagged ?? 0)} autostart entries flagged`,
      },
      {
        to: '/app/event-logs', label: 'Event logs', icon: ScrollText, tone: 'red',
        description: 'Windows event logs: logons, failed logons, account changes, cleared logs, services, PowerShell and USB, with Sigma detections.',
        count: (c) => c.event_records ?? 0,
        alert: (c) => (c.event_detections ?? 0) > 0,
        countLabel: (c) => `${n(c.notable_events ?? 0)} notable · ${n(c.event_detections ?? 0)} detections`,
      },
      {
        to: '/app/ntfs', label: 'File system journal', icon: FileClock, tone: 'amber',
        description: 'NTFS: files whose times look altered, alternate data streams (where downloads came from) and the USN change journal.',
        count: (c) => c.usn_records ?? 0,
        alert: (c) => (c.timestomp_suspects ?? 0) > 0,
        countLabel: (c) => `${n(c.timestomp_suspects ?? 0)} timestomped · ${n(c.alternate_streams ?? 0)} streams · ${n(c.usn_records ?? 0)} journal records`,
      },
      {
        to: '/app/computer', label: 'Computer and users', icon: Monitor, tone: 'teal',
        description: 'Computer name, Windows version, network, time zone and user accounts from the registry.',
        count: (c) => c.user_accounts ?? 0, countLabel: () => 'user accounts',
      },
      {
        to: '/app/indicators', label: 'Indicators', icon: ShieldAlert, tone: 'red',
        description: 'YARA matches, hash-set matches, renamed and encrypted files, activity patterns and statistical anomalies.',
        count: (c) => c.malware_indicators + (c.known_bad_files ?? 0) + (c.notable_files ?? 0) + c.patterns,
        alert: (c) => c.malware_indicators > 0 || (c.known_bad_files ?? 0) > 0,
        countLabel: (c) => `${n(c.malware_indicators)} YARA · ${n(c.known_bad_files ?? 0)} known bad · ${n(c.notable_files ?? 0)} notable · ${n(c.patterns)} patterns`,
      },
      {
        to: '/app/carving', label: 'File carving', icon: Layers,
        description: 'Recover files from unallocated space with PhotoRec or Scalpel.',
        count: (c) => c.carved_files, countLabel: () => 'carved files',
      },
      {
        to: '/app/found-data', label: 'Found data', icon: ScanSearch, tone: 'amber',
        description: 'Email, web and IP addresses, phone, card, IBAN, crypto and Aadhaar numbers found in the file contents.',
        count: (c) => c.found_data ?? 0, countLabel: () => 'values found',
      },
      {
        to: '/app/search', label: 'Keyword search', icon: Search,
        description: 'Search names and records, or the text inside files (with regular expressions).',
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
      { to: '/app/admin/hashsets', label: 'Hash sets', icon: Fingerprint, permission: 'HASHSET_MANAGE', noTile: true },
      { to: '/app/admin/system', label: 'System & tools', icon: Wrench, noTile: true },
    ],
  },
];
