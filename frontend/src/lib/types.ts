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
  programs_executed?: number;
  folders_browsed?: number;
  user_searches?: number;
  persistence_entries?: number;
  persistence_flagged?: number;
  installed_programs?: number;
  event_records?: number;
  notable_events?: number;
  event_detections?: number;
  jumplist_entries?: number;
  timeline_activities?: number;
  thumbnails?: number;
  srum_records?: number;
  search_index_entries?: number;
  search_entries_not_on_disk?: number;
  timestomp_suspects?: number;
  alternate_streams?: number;
  usn_records?: number;
  browser_searches?: number;
  browser_cookies?: number;
  browser_bookmarks?: number;
  browser_autofill?: number;
  browser_logins?: number;
  browser_recovered?: number;
  email_stores?: number;
  email_messages?: number;
  email_attachments?: number;
  chat_messages?: number;
  chat_calls?: number;
  chat_file_transfers?: number;
  chat_contacts?: number;
  chat_apps?: number;
  cloud_accounts?: number;
  cloud_files?: number;
  pictures?: number;
  videos?: number;
  media_with_gps?: number;
  ocr_files?: number;
  renamed_files?: number;
  encrypted_files?: number;
  known_bad_files?: number;
  notable_files?: number;
  found_data?: number;
  archive_members?: number;
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
  volume_id?: string;
  // From file processing (absent until the fileproc module has run).
  md5?: string;
  sha1?: string;
  sha256?: string;
  mime?: string;
  magic?: string;
  file_category?: string;
  ext_mismatch?: boolean;
  /** What the name suggests when the content contradicts it, e.g. "JPEG image". */
  expected_type?: string | null;
  entropy?: number;
  encryption?: { kind: 'ZIP' | 'OFFICE' | 'PDF' | 'HIGH_ENTROPY' | 'ARCHIVE'; detail: string } | null;
  hash_basis?: string;
  hash_error?: string | null;
  hash_status?: HashKind | null;
  hash_sets?: { set_id: string; name: string; kind: HashKind; algorithm: string }[];
  /** For a file taken out of an archive or document: where it came from. */
  container?: {
    kind: 'zip' | 'ooxml' | 'odf' | 'ole' | 'pdf' | '7z';
    parent: string;
    member: string;
    depth: number;
    encrypted: boolean;
    packed_size?: number | null;
    modified?: string | null;
    store?: string | null;
    note?: string | null;
  };
  /** For an archive or document: what it holds. */
  archive?: { kind: string; members?: number; extracted?: number; encrypted?: number; not_extracted?: number; names_encrypted?: boolean;
    error?: string; note?: string };
}

export type HashKind = 'KNOWN_GOOD' | 'KNOWN_BAD' | 'NOTABLE';

export type FoundKind = 'email' | 'url' | 'ip' | 'phone' | 'card' | 'iban' | 'crypto' | 'aadhaar';

export interface FoundOccurrence {
  path: string;
  inode: string;
  volume_id: string;
  partition_offset: number | null;
  deleted: boolean;
  method: string;
  member?: boolean;
  entry_id?: string | null;
  text_offset: number;
  byte_offset: number | null;
  byte_length: number | null;
  as_found?: string | null;
}

/** One value found in the file contents of one evidence item. Card and Aadhaar numbers come masked (no `value`). */
export interface FoundValue {
  _id: string;
  evidence_id: string;
  kind: FoundKind;
  label?: string;
  value?: string;
  display: string;
  sensitive: boolean;
  details: Record<string, string>;
  count: number;
  file_count: number;
  first?: string | null;
  occurrences?: FoundOccurrence[];
}

export interface ContentMatch {
  text_offset: number;
  byte_offset: number | null;
  byte_length: number | null;
  before: string;
  match: string;
  after: string;
}

export interface ContentHit {
  evidence_id: string;
  entry_id: string | null;
  path: string;
  inode: string;
  volume_id: string;
  partition_offset: number | null;
  deleted: boolean;
  size: number;
  method: 'text' | 'strings' | 'pdf' | 'ooxml' | 'odf' | 'rtf' | 'sqlite' | 'unallocated';
  member?: boolean;
  unallocated?: boolean;
  encoding?: string | null;
  truncated: boolean;
  match_count: number;
  matches: ContentMatch[];
}

export interface ContentResults {
  query: string;
  mode: 'text' | 'regex';
  total_files: number;
  total_matches: number;
  complete: boolean;
  files: ContentHit[];
  not_indexed: { evidence_id: string; filename?: string }[];
  elapsed_ms: number;
}

export interface HashSet {
  set_id: string;
  name: string;
  kind: HashKind;
  description?: string | null;
  status: 'IMPORTING' | 'READY' | 'FAILED';
  format?: string;
  count?: number;
  counts?: Record<'md5' | 'sha1' | 'sha256', number>;
  algorithms?: string[];
  invalid_lines?: number;
  error?: string | null;
  source_filename?: string;
  source_size?: number;
  source_sha256?: string;
  imported_by_name?: string;
  imported_at?: string;
  ready_at?: string;
  job_id?: string;
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
  eventlog_first_connected?: string | null;
  eventlog_last_connected?: string | null;
  eventlog_last_removed?: string | null;
  eventlog_events?: { time: string | null; action: string; log: string; event_id: number; record_id: number }[];
  source: string;
}

/** One record of a Windows event log (module eventlogs). */
export interface EventRecord {
  _id: string;
  evidence_id: string;
  nk: string;
  log: string;
  log_path: string;
  channel: string | null;
  provider: string | null;
  provider_guid?: string | null;
  event_id: number | null;
  qualifiers?: number | null;
  version?: number | null;
  level?: number | null;
  level_name?: string;
  task?: number | null;
  opcode?: number | null;
  keywords?: string | null;
  time: string | null;
  record_id: number | null;
  computer?: string | null;
  user_sid?: string | null;
  user?: string | null;
  process_id?: number | null;
  thread_id?: number | null;
  data: Record<string, string>;
  data_values: string[];
  user_data?: string;
  details?: Record<string, string>;
  category: string | null;
  title: string | null;
  description: string | null;
  notable: boolean;
  detections: string[];
  recovered: boolean;
  truncated?: boolean;
  parse_error?: string;
  xml?: string;
  xml_truncated?: boolean;
}

export interface EventLogInfo {
  evidence_id: string;
  path: string;
  name: string;
  channel: string | null;
  records: number;
  recovered: number;
  unreadable: number;
  first: string | null;
  last: string | null;
  size: number;
  sha256: string;
  dirty?: boolean;
  full?: boolean;
  corrupted?: boolean;
  capped: boolean;
  errors: string[];
}

export interface EventDetection {
  _id: string;
  evidence_id: string;
  rule_id: string;
  title: string;
  level: 'informational' | 'low' | 'medium' | 'high' | 'critical';
  description: string;
  tags: string[];
  references: string[];
  falsepositives: string[];
  count: number;
  first: string | null;
  last: string | null;
  group: Record<string, string> | null;
  sample: string[];
  rule_file: string;
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
