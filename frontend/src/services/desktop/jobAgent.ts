import { api } from '../api';
import { claimJob, completeJob, failJob, getDesktopJobs, pushOfflineData } from './sync';
import { sendHeartbeat } from './device';
import { runTool } from './forensicTools';
import { hashLocalFile } from './evidence';

const POLL_INTERVAL_MS = 30_000;
let agentTimer: ReturnType<typeof setInterval> | null = null;

async function processJob(job: any): Promise<void> {
  const { job_id, type, payload } = job;
  try {
    await api(`/desktop/jobs/${job_id}/start`, { method: 'POST' });

    let result: any;
    switch (type) {
      case 'DESKTOP_HASH_FILE': {
        const path = payload?.path || payload?.evidence_path;
        if (!path) throw new Error('No path provided in job payload');
        result = await hashLocalFile(path);
        break;
      }
      case 'DESKTOP_RUN_TOOL': {
        const { tool, args = [], timeout_seconds = 60 } = payload || {};
        if (!tool) throw new Error('No tool specified in job payload');
        result = await runTool(tool, args, timeout_seconds);
        break;
      }
      case 'DESKTOP_ACQUIRE_EVIDENCE': {
        // Acquisition workflow: hash the file, record as acquisition
        const path = payload?.path;
        if (!path) throw new Error('No evidence path provided in job payload');
        result = await hashLocalFile(path);
        result.acquired_path = path;
        result.acquisition_timestamp = new Date().toISOString();
        break;
      }
      default:
        throw new Error(`Unknown desktop job type: ${type}`);
    }

    await completeJob(job_id, result, `${type} completed successfully`);
  } catch (err: any) {
    await failJob(job_id, err?.message || String(err));
  }
}

async function agentTick(): Promise<void> {
  try {
    // Heartbeat
    await sendHeartbeat().catch(() => {});

    // Push any offline records
    await pushOfflineData().catch(() => {});

    // Check for and process pending desktop jobs
    const { data: jobs } = await getDesktopJobs();
    for (const job of jobs.slice(0, 3)) {
      // Claim and process one at a time (up to 3 per tick)
      try {
        await claimJob(job.job_id);
        processJob(job); // fire and forget -- don't await so we don't block heartbeat
      } catch {
        // Job may have been claimed by another desktop instance
      }
    }
  } catch {
    // Network offline or auth error -- will retry on next tick
  }
}

export function startJobAgent(): void {
  if (agentTimer) return; // already running
  agentTick(); // immediate first tick
  agentTimer = setInterval(agentTick, POLL_INTERVAL_MS);
}

export function stopJobAgent(): void {
  if (agentTimer) {
    clearInterval(agentTimer);
    agentTimer = null;
  }
}
