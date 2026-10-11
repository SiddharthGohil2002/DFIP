export type Role = 'ADMIN' | 'INVESTIGATOR' | 'ANALYST' | 'VIEWER';

export interface User {
  _id: string;
  name: string;
  email: string;
  role: Role;
  status: string;
  permissions: string[];
}

export interface CaseItem {
  _id: string;
  case_id: string;
  name: string;
  description?: string;
  status: string;
  priority: string;
  investigator_id?: string | null;
  created_by?: string;
  created_at: string;
  updated_at: string;
  demo?: boolean;
  legal_hold?: LegalHold;
}

export interface LegalHold {
  active: boolean;
  reason: string;
  set_by_name?: string;
  set_at?: string;
  released_by_name?: string;
  released_at?: string;
  release_reason?: string;
}

export interface AnalysisSummary {
  files?: number;
  deleted_files?: number;
  timeline_events?: number;
  browser_history?: number;
  browser_downloads?: number;
  usb_devices?: number;
  programs_run?: number;
  recent_files?: number;
  recycle_bin_items?: number;
  files_scanned?: number;
  yara_matches?: number;
  patterns?: number;
  anomalies_flagged?: number;
}

export interface Evidence {
  _id?: string;
  evidence_id: string;
  case_id?: string;
  filename: string;
  format: string;
  size: number;
  sha256: string;
  sha512?: string;
  verification_status: string;
  verified_at?: string;
  analysis_status?: string;
  analysis_summary?: AnalysisSummary;
  last_analysis_job?: string;
  analyzed_at?: string;
  created_at: string;
  created_by?: string;
  storage_path?: string;
  demo?: boolean;
  /** Each analysis module's latest run on this evidence. */
  modules?: Record<string, ModuleStatus>;
  /** The time zone the last analysis read local times in (FAT file times, setupapi.dev.log). */
  time_zone?: EvidenceTimeZone | null;
}

export interface EvidenceTimeZone {
  zone: string;
  source: 'registry' | 'override' | 'default';
  detected?: { key_name?: string | null; iana?: string | null; posix?: string; zone?: string; bias?: number } | null;
  override?: { zone: string; reason: string; set_by_name?: string; set_at?: string } | null;
}

export interface UserAccount {
  _id: string;
  sid?: string | null;
  rid?: number;
  username?: string | null;
  full_name?: string | null;
  comment?: string | null;
  last_logon?: string | null;
  logon_count?: number;
  password_last_set?: string | null;
  disabled?: boolean;
  profile_path?: string | null;
  profile_last_loaded?: string | null;
  source: 'SAM' | 'PROFILE_LIST';
}

export interface ComputerEntry {
  evidence_id: string;
  filename?: string;
  computer?: {
    computer_name?: string | null;
    hostname?: string | null;
    domain?: string | null;
    last_shutdown?: string | null;
    machine_sid?: string | null;
    last_logged_on_user?: string | null;
    os?: { product_name?: string; edition?: string; display_version?: string; build?: string; ubr?: number; install_date?: string;
      registered_owner?: string; registered_organization?: string | null };
    interfaces?: { guid: string; dhcp: boolean; ip: string; subnet_mask?: string; gateway?: string; dhcp_server?: string; domain?: string; lease_obtained?: string }[];
    time_zone?: EvidenceTimeZone['detected'];
    hives?: { hive: string; path: string; sha256: string; size: number }[];
  } | null;
  accounts: UserAccount[];
  time_zone?: EvidenceTimeZone | null;
}

export interface ModuleStatus {
  status: 'QUEUED' | 'RUNNING' | 'COMPLETED' | 'FAILED' | 'CANCELLED';
  job_id?: string;
  run_id?: string;
  version?: string;
  counts?: Record<string, number>;
  warnings?: string[];
  warnings_total?: number;
  error?: string | null;
  started_at?: string;
  finished_at?: string | null;
}

/** GET /jobs/analysis/modules: what an analysis job can run. */
export interface AnalysisCatalog {
  modules: { name: string; label: string; description: string; requires: string[]; version: string }[];
  profiles: { name: string; label: string; modules: string[] }[];
  default_profile: string;
}

export interface Job {
  job_id: string;
  type: string;
  status: string;
  progress?: number;
  stage?: string;
  error?: string;
  payload?: { evidence_id?: string };
  result?: any;
  created_at: string;
  finished_at?: string;
}

export interface CaseCounts {
  evidence: number;
  evidence_analyzed: number;
  files: number;
  deleted_files: number;
  recovered_files: number;
  carved_files: number;
  timeline_events: number;
  browser_history: number;
  browser_downloads: number;
  usb_devices: number;
  programs_run: number;
  recent_files: number;
  recycle_bin_items: number;
  user_accounts?: number;
  malware_indicators: number;
  patterns: number;
  anomalies_flagged: number;
  findings: number;
  tags: number;
  reports: number;
  custody_events: number;
}

export interface CaseOverview {
  case: CaseItem;
  evidence: Evidence[];
  counts: CaseCounts;
  jobs: Job[];
}

export interface FsEntry {
  _id: string;
  evidence_id: string;
  path: string;
  name: string;
  inode: string;
  size: number | null;
  is_dir: boolean;
  deleted: boolean;
  deleted_status?: string | null;
  partition_offset: number;
  filesystem_type?: string;
  mtime?: string | null;
  atime?: string | null;
  ctime?: string | null;
  crtime?: string | null;
}

export interface TimelineEvent {
  _id: string;
  evidence_id: string;
  timestamp: string;
  type: string;
  description: string;
  source?: string;
  macb?: string;
  deleted?: boolean;
  serial?: string;
}

export interface UsbDevice {
  _id: string;
  evidence_id: string;
  instance_id: string;
  serial: string;
  serial_is_unique?: boolean;
  device_class_id?: string;
  vendor?: string;
  product?: string;
  revision?: string;
  friendly_name?: string | null;
  vid?: string | null;
  pid?: string | null;
  drive_letters?: string[];
  volume_guids?: string[];
  control_sets?: string[];
  registry_key?: string | null;
  first_install?: string | null;
  last_install?: string | null;
  last_arrival?: string | null;
  last_removal?: string | null;
  setupapi_first_install?: string | null;
  source: string;
}

export interface Artifact {
  _id: string;
  artifact_id?: string;
  case_id: string;
  evidence_id: string;
  type: string;
  filename?: string;
  original_path?: string;
  path?: string;
  size?: number;
  sha256?: string;
  inode?: string;
  was_deleted?: boolean;
  source?: string;
  timestamp?: string;
  [key: string]: any;
}

export interface Finding {
  _id: string;
  case_id: string;
  title: string;
  description: string;
  severity: string;
  evidence_ids: string[];
  created_by?: string;
  created_at: string;
}

export interface Report {
  _id: string;
  report_id: string;
  case_id: string;
  version: number;
  sha256: string;
  created_at: string;
  created_by?: string;
}
