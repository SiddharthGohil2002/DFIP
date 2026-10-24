# DFIP — Digital Forensics Investigation Platform

DFIP is a production-oriented digital-forensics case-management and examination suite with a MongoDB system of record, immutable evidence workflow, SHA-256 integrity verification, chain of custody, tamper-evident audit logging, RBAC, background analysis jobs, specialist-tool adapters, investigator workspaces, administration, WebSockets, and forensic reporting.

> **New here?** Go straight to [Run DFIP with Docker (step-by-step)](#run-dfip-with-docker-step-by-step). It takes you from an empty computer to a running DFIP, one command at a time.

## Architecture

- **UI:** one React 19 + TypeScript + Vite codebase (`frontend/`) built twice: the **web** portal (public website + sign-in + workspace, served by nginx) and the **desktop** app (sign-in + workspace only, inside the Tauri 2 shell in `desktop/`)
- **API:** FastAPI + Pydantic
- **Database:** MongoDB with indexes and migration-safe startup
- **Evidence:** filesystem-backed original store with SHA-256 manifest and read-only permissions
- **Jobs:** Celery workers on Redis; job state in MongoDB
- **Analysis:** 28 analysis modules (`backend/app/forensic/modules/`) in three profiles (quick, standard, full), run by Celery workers; external tools (The Sleuth Kit, libyal tools, tshark, Volatility 3, ClamAV, capa, ExifTool, ffmpeg, Tesseract, 7-Zip and others) run without a shell, in their own process group, under time and memory limits
- **Security:** JWT access/refresh tokens, PBKDF2-SHA256 password hashing, RBAC, audit hash chain, CORS controls
- **Reporting:** report templates; signed PDF (PAdES, optional RFC 3161 timestamp) and the same content as HTML, each with its SHA-256; tables as CSV and XLSX, the case as CASE/UCO JSON-LD, indicators as STIX 2.1 and MISP
- **Realtime:** authenticated WebSocket notifications
- **Deployment:** Docker Compose, Nginx static frontend, health checks

## Run DFIP with Docker (step-by-step)

This guide assumes you have never used Docker before. Follow the steps in order and do not skip any. You type every command into a **terminal**:

- **Windows:** use **PowerShell**. Press the Start button, type `PowerShell` and press Enter. (Do not use Git Bash for these commands.)
- **macOS:** use **Terminal** (Applications → Utilities → Terminal).
- **Linux:** use your usual terminal app.

When a command is different on Windows and on macOS/Linux, both versions are shown. Type (or paste) one command, press Enter, and wait for it to finish before typing the next one.

### What you will have at the end

Docker runs DFIP as six **containers**. A container is a small, isolated program package that brings everything it needs with it. You do **not** install Python, Node.js, MongoDB, Redis or any forensic tool yourself; Docker builds and runs all of them for you.

| Container | What it does | Where you reach it |
|---|---|---|
| `dfip-frontend` | The website and the investigator workspace (nginx) | http://localhost |
| `dfip-backend` | The API that the website talks to (FastAPI) | http://localhost:8000 |
| `dfip-celery-worker` | Runs the forensic analysis jobs in the background | — |
| `dfip-celery-beat` | Starts scheduled work (the daily retention check) | — |
| `dfip-mongodb` | The database (cases, evidence records, results) | port 27017 |
| `dfip-redis` | The job queue between the API and the worker | — |

Uploaded evidence, analysis output and reports are saved in the `storage/` folder of the project, so you can see them on your own disk.

### Step 0: Check your computer

- **Operating system:** 64-bit Windows 10 or 11, macOS, or Linux.
- **Memory:** 8 GB RAM or more is recommended.
- **Disk space:** at least **10 GB free**. The finished Docker images take about 4 GB (the backend image alone is about 2.5 GB because it contains all the forensic tools), and the evidence you upload is stored on top of that.
- **Internet:** needed for the first build, which downloads the base images and tools.
- **Free ports:** 80, 8000 and 27017 must not be used by another program. If one is, see [Troubleshooting](#troubleshooting).

### Step 1: Install Git

Git is the tool that downloads (clones) the project code.

- **Windows:** download Git from https://git-scm.com/download/win, run the installer and keep all the default options.
- **macOS:** run `git --version`. If Git is missing, macOS offers to install the "Command Line Developer Tools"; click **Install**.
- **Linux (Ubuntu/Debian):** `sudo apt update && sudo apt install -y git`

Check that it worked (close and reopen the terminal first on Windows):

```bash
git --version
```

You should see something like `git version 2.x.x`.

### Step 2: Install Docker and start it

- **Windows:** install **Docker Desktop** from https://www.docker.com/products/docker-desktop/. During setup keep **"Use WSL 2 instead of Hyper-V"** ticked, and restart the computer when asked. If Docker Desktop later says WSL is missing or too old, open PowerShell **as Administrator** (right-click PowerShell → *Run as administrator*), run `wsl --install` (or `wsl --update`), and restart again.
- **macOS:** install **Docker Desktop** from the same page. Pick the download that matches your Mac's chip (Apple silicon or Intel).
- **Linux:** install **Docker Engine** and the **Docker Compose plugin** by following https://docs.docker.com/engine/install/ for your distribution. Then let your user run Docker without `sudo`: run `sudo usermod -aG docker $USER`, then log out and log back in.

**Start Docker.** On Windows and macOS, open the **Docker Desktop** app and wait until it shows **Engine running** at the bottom left. Docker must be running every time you use DFIP. The commands below fail if it is not.

Check that Docker works:

```bash
docker --version
docker compose version
docker run --rm hello-world
```

The first two commands print version numbers. The last one prints `Hello from Docker!`. If you see `Cannot connect to the Docker daemon` or `failed to connect to the docker API`, Docker is not running yet: start Docker Desktop, wait for **Engine running**, and try again.

> Use `docker compose` (with a space). The old `docker-compose` command (with a dash) is outdated and is not used in this guide.

### Step 3: Download the project

Go to the folder where you want the project (for example your Documents folder), then clone it:

```bash
cd ~/Documents
git clone https://github.com/SiddharthGohil2002/DFIP.git
cd DFIP
```

`cd ~/Documents` works in PowerShell, macOS and Linux. **Run every remaining command from inside this `DFIP` folder.** To check that you are in the right place, run `ls`: you should see `docker-compose.yml`, `backend`, `frontend` and `storage` in the list.

### Step 4: Create your settings file (`.env`)

DFIP reads its settings from a file named `.env`. The project ships a template called `.env.example`; copy it:

| Windows (PowerShell) | macOS / Linux |
|---|---|
| `Copy-Item .env.example .env` | `cp .env.example .env` |

**For a first run on your own computer you do not need to change anything.** Demo mode is switched on, and demo accounts are created for you.

If other people can reach your computer over the network, change the passwords **before Step 6**. Open `.env` in a text editor (`notepad .env` on Windows, `open -e .env` on macOS, `nano .env` on Linux) and replace these three values with your own long random text:

- `JWT_SECRET`: at least 32 characters
- `MONGO_ROOT_PASSWORD`
- `REDIS_PASSWORD`

To generate random text, use `[guid]::NewGuid().ToString('N') + [guid]::NewGuid().ToString('N')` in PowerShell, or `openssl rand -hex 32` on macOS/Linux.

> **Important:** MongoDB stores its password the **first** time it starts. If you change `MONGO_ROOT_PASSWORD` after DFIP has already run once, the backend can no longer sign in to the database. Either set it before the first start, or reset the database as described in [Step 10](#step-10-everyday-commands).

`.env` holds your secrets, so it is listed in `.gitignore` and never uploaded to GitHub.

### Step 5 (Linux only): Let the containers write to `storage/`

The backend runs inside its container as user ID `10001` and needs to write evidence and reports into `storage/`. On Linux, give that user ownership of the folder:

```bash
sudo chown -R 10001:10001 storage
```

Windows and macOS users skip this step.

### Step 6: Build and start DFIP

```bash
docker compose up -d --build
```

What the parts mean:

- `up` creates and starts all six containers.
- `-d` (detached) runs them in the background, so you get your terminal back.
- `--build` builds the DFIP images from the code in this folder.

**The first build takes a while** (often 10–30 minutes, depending on your internet speed), because Docker downloads base images and installs many forensic tools. You will see a lot of output scrolling by; that is normal. Later starts take only seconds. If the build stops with a network error, run the same command again: Docker continues from the steps that already finished.

The command is done when you see lines like these and get your prompt back:

```
 ✔ Container dfip-redis           Healthy
 ✔ Container dfip-mongodb         Healthy
 ✔ Container dfip-celery-beat     Started
 ✔ Container dfip-backend         Healthy
 ✔ Container dfip-celery-worker   Started
 ✔ Container dfip-frontend        Started
```

> **Windows shortcut:** `.\start-dfip.ps1` does Steps 4 and 6 for you. It creates `.env` if it is missing, starts DFIP, waits until it is ready, and opens your browser. Use `.\start-dfip.ps1 -Rebuild` after you download new code. If PowerShell says *"running scripts is disabled on this system"*, run it like this instead: `powershell -ExecutionPolicy Bypass -File .\start-dfip.ps1`

### Step 7: Check that everything is running

```bash
docker compose ps
```

You should see all six containers with a **STATUS** of `Up`. The three that have health checks (`dfip-backend`, `dfip-mongodb` and `dfip-redis`) should also show `(healthy)`. Your output has a few more columns than this example:

```
NAME                 SERVICE         STATUS
dfip-backend         backend         Up 2 minutes (healthy)
dfip-celery-beat     celery_beat     Up 2 minutes
dfip-celery-worker   celery_worker   Up 2 minutes
dfip-frontend        frontend        Up 2 minutes
dfip-mongodb         mongodb         Up 2 minutes (healthy)
dfip-redis           redis           Up 2 minutes (healthy)
```

If a container shows `(health: starting)`, wait a minute and run the command again.

Then open http://localhost:8000/health in your browser. You should see:

```json
{"status":"ok","database":"mongodb","version":"2.1.0","demo_mode":true,"require_desktop_for_writes":false,"registration_mode":"approval"}
```

`"status":"ok"` means the API is running and connected to the database. If it says `"degraded"` instead, see [Troubleshooting](#troubleshooting).

### Step 8: Open DFIP and sign in

1. Open **http://localhost** in your browser. You see the DFIP website.
2. Click **Sign in** (top right).
3. Under **Demo accounts**, click one of the accounts. Its email and password are filled in for you. Then click the sign-in button.

| Account | Password | Role |
|---|---|---|
| `investigator@dfip.local` | `DemoPassword!2026` | Investigator: full case work (start with this one) |
| `analyst@dfip.local` | `DemoPassword!2026` | Analyst: analysis and findings |
| `viewer@dfip.local` | `DemoPassword!2026` | Viewer: read only |
| `admin@dfip.local` | `DemoPassword!2026` | Administrator: everything, plus user management |

These accounts exist **only while `DEMO_MODE=true`**. They are for trying DFIP on your own computer. Turn demo mode off before real use (see [Settings you can change](#settings-you-can-change)).

### Step 9 (optional): Analyse a sample disk image

You need a disk image to analyse. The project can generate a small (64 MiB) Windows-like test disk with known deleted files, browser history, USB devices and more. From the `DFIP` folder:

```bash
docker run --rm -v "${PWD}:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-test-image.sh
```

This command works as written in PowerShell, macOS and Linux. It takes a few minutes and creates `storage/test-images/dfip-test-disk.dd`.

Then, in DFIP (signed in as the investigator):

1. Click **New case**, enter a name, and click **Create case**.
2. On the case's home screen, click **Add evidence**, choose `storage/test-images/dfip-test-disk.dd`, and click **Upload and seal**. DFIP calculates the file's SHA-256 and SHA-512 and stores it read-only.
3. Click **Run analysis**. Progress appears on the case's home screen. A small test disk finishes within a few minutes.
4. Explore the results: Files, Timeline, Browser history, USB devices, Windows activity and more.

The full investigation workflow is described in [Forensic workflow](#forensic-workflow) below.

### Step 10: Everyday commands

Run these from the `DFIP` folder:

| I want to… | Command |
|---|---|
| Stop DFIP (all data is kept) | `docker compose stop` (Windows: `.\stop-dfip.ps1`) |
| Start it again | `docker compose up -d` |
| See what is running | `docker compose ps` |
| Watch the logs of the API | `docker compose logs -f backend` (press `Ctrl+C` to stop watching) |
| Watch the logs of the analysis worker | `docker compose logs -f celery_worker` |
| Update to the newest code | `git pull`, then `docker compose up -d --build` |
| Remove the containers but keep the data | `docker compose down` |
| **Delete everything**, including the database | `docker compose down -v`. Uploaded files stay in `storage/`; delete them yourself if you also want those gone |

`docker compose logs` uses the **service** names (`backend`, `celery_worker`, `frontend`, `mongodb`, `redis`, `celery_beat`), not the container names.

### After setup: turn on the optional features

As soon as you can sign in (Step 8), these work with nothing extra: cases, evidence upload with SHA-256/SHA-512 and chain of custody, all disk, file, registry, browser, email, chat, phone and network analysis, DFIP's built-in YARA rules, findings, signed PDF/HTML reports and every export.

A few features need a **one-time step by an administrator**. Sign in as `admin@dfip.local`, because these actions need administrator rights. The downloads need internet access on the computer running DFIP.

| Feature | Until you do the step | How to turn it on |
|---|---|---|
| **ClamAV virus scan** | The ClamAV scan is skipped during analysis (the Malware rules page says so) | Administration → **Malware rules** → **Download official databases**. It runs as a background job. Repeat it now and then to get new signatures. On a computer without internet, copy the database files (`main.cvd`, `daily.cvd`, `bytecode.cvd`) from elsewhere and use **Add a database file** on the same page. |
| **Windows memory images** (Volatility) | Volatility cannot read Windows memory images, because it needs the symbols of the exact Windows kernel | Administration → **System & tools** → *Memory analysis symbols* → **Download the Windows pack** (a large download). Or set `MEMORY_SYMBOL_SERVER=true` in `.env` so Volatility fetches the symbols it needs from Microsoft's symbol server (it sends the kernel's name and ID there). |
| **Linux and macOS memory images** | Volatility has no symbols for them | Same card → **Add a symbol pack**: a ZIP with Volatility symbol tables (ISF files in `linux/` or `mac/` folders) made for that exact kernel. |
| **Your own YARA rules** | Only DFIP's built-in rules are used | Administration → **Malware rules** → **Add a rule set** (a `.yar` file). |
| **Hash sets** such as the NIST NSRL | Files are not marked as known good, known bad or notable | Administration → **Hash sets** → **Import a hash set**. Accepted: a text file with one MD5, SHA-1 or SHA-256 per line (`sha256sum` output works), a CSV with `md5`/`sha1`/`sha256` columns, or the NSRL RDS v3 SQLite file. Large files (such as the NSRL) are too big to upload: copy them into `storage/hashsets/incoming/` and import them from *Files on the server* on the same page. |

These features need **your own key or certificate** in `.env`. After editing `.env`, run `docker compose up -d` so DFIP restarts with the new values. All of them are optional, and DFIP stays fully offline without them.

| Feature | Setting in `.env` | Where you use it |
|---|---|---|
| **VirusTotal** lookups of program hashes | `VIRUSTOTAL_API_KEY` (a free key from virustotal.com allows 4 lookups a minute, which is the default `VIRUSTOTAL_RATE_PER_MINUTE`) | In a case: **Indicators** → tick *Look up program hashes on VirusTotal for this case*. Only SHA-256 hashes are sent. |
| **AbuseIPDB**, **AlienVault OTX** and **URLhaus** lookups of addresses | `ABUSEIPDB_API_KEY`, `OTX_API_KEY`, `URLHAUS_API_KEY` | In a case: **Network** → **Look up** next to a host or IP address. |
| **Claude mode** (ask questions about the case summary) | `ANTHROPIC_API_KEY` (from console.anthropic.com) | In a case: **Case summary** → **Turn on for this case**, tick facts, type a question, **Ask Claude**. Only the ticked facts and the question are sent. See [docs/ai.md](docs/ai.md). |
| **Trusted report signatures** | Copy your organisation's PKCS#12 file into `storage/signing/` and set `REPORT_SIGNING_P12=/app/storage/signing/<file name>` and `REPORT_SIGNING_P12_PASSWORD` | Every new report PDF is signed with your certificate. Without one, DFIP signs reports with a self-signed certificate that verification shows as *not trusted*. |
| **Trusted signing time** on reports | `REPORT_TSA_URL` (an RFC 3161 timestamp authority) | Every new report PDF also gets a timestamp from that authority. |
| **Checking signatures against your own roots** | `REPORT_TRUST_ROOTS`, `REPORT_TSA_TRUST_ROOTS` (PEM files, also in `storage/signing/`, written as `/app/storage/signing/<file name>`) | Report verification then shows signatures from those roots as trusted. |

`storage/` and `.env` are never uploaded to GitHub, so your certificates and keys stay on your computer.

### Build the Windows desktop app (optional)

DFIP also has a Windows app, *DFIP Investigator*, which connects to this server. It is **not** built by `docker compose`. Until you build it, the website and the sign-in page offer no download. You only need Docker to build it:

1. Open a terminal that has `sh`. On Windows that is **Git Bash**, which was installed with Git in Step 1 (Start → type `Git Bash`). On macOS/Linux use your normal terminal.
2. Go to the project folder, for example `cd ~/Documents/DFIP`.
3. Run:

   ```bash
   sh desktop/scripts/build-windows-docker.sh
   ```

The first build takes a long time, because it downloads a Rust toolchain and the Windows SDK and compiles the app. Later builds are much faster. When it finishes, it prints the installer's SHA-256 and leaves the installer in `storage/downloads/`, named like `DFIP-Investigator_2.1.0_x64-setup.exe`. DFIP then offers it automatically on the website, on the sign-in page and in the workspace sidebar, with its SHA-256.

Install it on a Windows PC and enter the server address on its sign-in page: `http://localhost:8000` on the same computer, or `http://<server IP address>:8000` from another computer on the network. The installer is not code-signed, so Windows SmartScreen may warn you; click **More info** → **Run anyway**. Sign it before you give it to other people (see [releases/README.md](releases/README.md)). To build natively on Windows with Rust instead, see [desktop/INSTALL.md](desktop/INSTALL.md).

### Move DFIP to another computer (or make a backup)

Your cases are **not** in Git, so cloning the project on a new computer gives you an empty DFIP (in demo mode, it has only the demo case). The data lives in three places on the computer that runs DFIP, and you need **all three**:

1. the **database**, inside Docker;
2. the **`storage/` folder**: evidence files, reports, the report signing key, hash sets, rules and symbol packs;
3. the **`.env` file**: its secrets unlock stored keys (such as the passwords of encrypted volumes and the report signing key), and its MongoDB password must match the database.

**On the old computer**, with DFIP running, run these from the `DFIP` folder:

```bash
docker compose exec mongodb sh -c 'mongodump -u $MONGO_INITDB_ROOT_USERNAME -p $MONGO_INITDB_ROOT_PASSWORD --authenticationDatabase admin --db dfip --gzip --archive=/tmp/dfip-db.archive'
docker compose cp mongodb:/tmp/dfip-db.archive dfip-db.archive
docker compose stop
```

The first command writes the database into one file inside the database container, and the second copies it into the `DFIP` folder as `dfip-db.archive`. Now copy **`.env`**, **`dfip-db.archive`** and the whole **`storage`** folder to the new computer, for example with a USB drive.

**On the new computer:**

1. Do Steps 0–3: install Git and Docker, and clone the project.
2. Put the copied `.env` and `dfip-db.archive` into the new `DFIP` folder, and copy the **contents** of the old `storage` folder into the new `storage` folder (replace files when asked). **Skip Step 4.** Copying `.env.example` would overwrite your `.env`.
3. Linux only: do Step 5.
4. Do Step 6 (`docker compose up -d --build`) and wait until it has finished.
5. Load the database back in, then restart the API and the workers:

   ```bash
   docker compose cp dfip-db.archive mongodb:/tmp/dfip-db.archive
   docker compose exec mongodb sh -c 'mongorestore -u $MONGO_INITDB_ROOT_USERNAME -p $MONGO_INITDB_ROOT_PASSWORD --authenticationDatabase admin --drop --gzip --archive=/tmp/dfip-db.archive'
   docker compose restart backend celery_worker celery_beat
   ```

   The restore ends with `... document(s) restored successfully. 0 document(s) failed to restore.` Sign in with the same accounts as on the old computer. Your cases, evidence and reports are back, and **Verify** on an evidence item confirms its hash still matches.

> If you started DFIP on the new computer **before** putting the old `.env` in place, MongoDB has already saved a different password. Run `docker compose down -v` (this deletes only the new, empty database), put the old `.env` in the folder, and do steps 4–5 again.

**To make a backup** instead of moving: do the "old computer" part, keep `.env`, `dfip-db.archive` and a copy of `storage/` somewhere safe, then start DFIP again with `docker compose up -d`. `dfip-db.archive` is listed in `.gitignore`, so it cannot be committed by accident.

These commands work in PowerShell, macOS and Linux as written.

### Running on Linux, macOS and Apple silicon

- **Windows 10/11 (Intel or AMD processor):** follow the guide as written. This is the platform DFIP is developed and tested on.
- **Linux (Intel or AMD processor):** the same steps. [Step 5](#step-5-linux-only-let-the-containers-write-to-storage) is required, and you need `sudo` before `docker` unless your user is in the `docker` group (Step 2).
- **Intel Macs:** the same steps.
- **Apple silicon Macs (M1 and later) and ARM Linux:** every DFIP component and forensic tool is available for ARM, so the images build and run natively, with one exception: **capa**, the "what can this program do" check on the Indicators page. capa is published for Intel/AMD processors only, so on ARM its result shows as *failed* for each program, and the rest of the analysis is not affected. If you need capa, build the Intel/AMD images instead. They run under emulation, which is slower:

  ```bash
  DOCKER_DEFAULT_PLATFORM=linux/amd64 docker compose up -d --build
  ```

### Tool versions

The Python packages, capa and the website's npm packages are pinned to exact versions. The base images (`python:3.11-slim`, `mongo:8`, `redis:7-alpine`, `node:22-alpine`, `nginx:1.27-alpine`) and the Debian packages of the forensic tools are not, so a rebuild months later can pick up newer tool versions. After such a rebuild, run the backend's test suite. It takes about half a minute and should end with `passed` and no `failed`:

```bash
docker run --rm dfip-backend python -m pytest -q
```

(`dfip-backend` is the image name when the project folder is called `DFIP`, as in Step 3.)

### Troubleshooting

| Problem | What to do |
|---|---|
| `Cannot connect to the Docker daemon` / `failed to connect to the docker API` | Docker is not running. Start Docker Desktop and wait for **Engine running**. |
| `port is already allocated` / `ports are not available` / `address already in use` | Another program (another web server, IIS, Skype, or a second copy of DFIP) is using port 80, 8000 or 27017. Stop that program, or change the left-hand number in `docker-compose.yml`, for example `ports: ["8080:80"]`, and then open http://localhost:8080. (`start-dfip.ps1` always checks port 80, so use the `docker compose` commands if you change it.) |
| http://localhost shows *502 Bad Gateway* or says the server is not reachable | The backend is still starting. Wait a minute, then refresh. Check `docker compose ps`. |
| `dfip-backend` is `unhealthy` or keeps restarting | Read its log: `docker compose logs backend`. |
| Backend log shows `Authentication failed` from MongoDB | `MONGO_ROOT_PASSWORD` in `.env` was changed after the first start. Put the old value back, **or** reset the database with `docker compose down -v` (this deletes all cases) and run `docker compose up -d` again. |
| Backend log shows a `JWT_SECRET` or `ADMIN_PASSWORD` error | You set `DEMO_MODE=false`. That mode needs a real `JWT_SECRET` (32+ characters) and an `ADMIN_PASSWORD` (12+ characters) in `.env`. |
| Linux: `Permission denied` on `/app/storage` | Do [Step 5](#step-5-linux-only-let-the-containers-write-to-storage). |
| The build fails while downloading packages | Check your internet connection (and proxy/VPN), then run `docker compose up -d --build` again. |
| `no space left on device` | Free some disk space. `docker system prune` removes stopped containers, unused images and the build cache. It keeps your DFIP database as long as you do **not** add `--volumes`. |
| An analysis stops and a container shows exit code `137` | Docker ran out of memory. Close other programs or give Docker more memory (Docker Desktop → Settings → Resources; on Windows with WSL 2 this is set in `%UserProfile%\.wslconfig`). |
| `running scripts is disabled on this system` (Windows) | Run `powershell -ExecutionPolicy Bypass -File .\start-dfip.ps1`, or use the `docker compose` commands directly. |
| Apple silicon Mac or ARM Linux: capa shows *failed* with `exec format error` | capa is published for Intel/AMD processors only. See [Running on Linux, macOS and Apple silicon](#running-on-linux-macos-and-apple-silicon). |
| A feature says it has no database, symbols or key | See [After setup: turn on the optional features](#after-setup-turn-on-the-optional-features). |
| `git clone` gives an empty DFIP on a new computer | Cases are not stored in Git. See [Move DFIP to another computer](#move-dfip-to-another-computer-or-make-a-backup). |

### Settings you can change

All settings live in `.env` (the full list with comments is in `.env.example`). After you edit `.env`, run `docker compose up -d` so the containers restart with the new values.

- **Demo mode:** keep `DEMO_MODE=true` for a first try. With `DEMO_MODE=false`, the backend refuses to start with a placeholder `JWT_SECRET` and requires `ADMIN_PASSWORD` for the initial `admin@dfip.local` account. Disable demo mode and remove or rotate the demo identities before production deployment.
- **Who may change data:** writes (cases, uploads, analysis, findings, reports) are allowed from the web portal and enforced by RBAC. Set `REQUIRE_DESKTOP_FOR_WRITES=true` to restrict writes to registered DFIP desktop workstations; the web portal reads this from `/health` and becomes read-only.
- **New accounts:** users can create an account from the sign-in page (web and desktop). With the default `REGISTRATION_MODE=approval`, a new account stays pending until an administrator approves it and picks its role (Users page). `open` activates accounts immediately as investigators, and `disabled` hides the option. Sign-in is required every time the desktop app starts and in every new browser session.
- **API keys, certificates and memory symbols:** see [After setup: turn on the optional features](#after-setup-turn-on-the-optional-features).

## Forensic workflow

1. Create a case.
2. Acquire/export the source image using your approved acquisition procedure.
3. Upload the evidence: a disk image (E01 with its segments, raw or split raw, VHD, VHDX, VMDK, QCOW2, AFF), a collection of files (ZIP or TAR: KAPE, Velociraptor, phone extractions), a network capture (pcap, pcapng) or a memory image (raw, crash dump, LiME).
4. DFIP computes SHA-256 and records acquisition metadata.
5. The original object is marked immutable and written read-only at the filesystem layer.
6. Verify integrity whenever required.
7. Run the analysis as a background job with a profile (Quick triage, Standard, Full) or chosen modules; unlock encrypted volumes with their key when needed.
8. Use specialist adapters when their tools are installed.
9. Review the results: files and their hashes, content search, timeline, browser, USB, Windows activity and registry, event logs, NTFS internals, shadow copies, email, chat and cloud, pictures, programs and malware indicators, Linux and macOS, network captures, phones and memory images; the link graph and the case summary.
10. Create evidence-linked findings, with pictures; have another investigator review and approve them.
11. Generate a signed report from a template (PDF and HTML, SHA-256 recorded); export tables, the case (CASE/UCO) or its indicators (STIX, MISP).
12. Review the chain of custody and tamper-evident audit chain.

## Production hardening checklist

- Use dedicated encrypted evidence storage / WORM object storage.
- Place DFIP behind TLS and a hardened reverse proxy.
- Use a private MongoDB network and encrypted MongoDB deployment.
- Rotate JWT and MongoDB secrets through a secrets manager.
- Disable demo mode and create named accounts with strong passwords.
- Add enterprise identity federation (OIDC/SAML) if required.
- Deploy the worker separately from the API for high-volume cases.
- Add malware-analysis VMs/sandboxes outside the API host; never execute submitted evidence inside the web process.
- Add centralized logs, metrics, backups, retention policies and disaster recovery.
- Validate forensic procedures and admissibility requirements against the applicable jurisdiction and agency SOPs.

## Testing

Backend syntax checks are safe to run offline:

```bash
python -m compileall backend/app
```

With dependencies available:

```bash
cd backend
pytest -q
```

Or inside the backend image (no local Python needed): `docker compose build backend && docker run --rm dfip-backend python -m pytest -q`.

End-to-end check of the analysis pipeline against a running stack, using a generated Windows-like test disk:

```bash
docker run --rm -v "$PWD:/repo" -w /repo python:3.11-slim sh scripts/test-image/make-test-image.sh
python scripts/test-image/e2e_analysis.py        # uploads, analyzes, recovers, reports
```

See `docs/forensic-engine.md` for the pipeline stages and known limitations.

Full functional testing (isolated API suite with ground-truth checks, browser suites for web and desktop UI, desktop app): see [tests/README.md](tests/README.md). In short: `sh tests/system/run.sh` and `sh tests/ui/run.sh`.

UI (both targets; `tsc` runs with strict unused-code checks):

```bash
cd frontend
npm ci
npm run build           # web portal  -> frontend/dist
npm run build:desktop   # desktop UI  -> frontend/dist-desktop
```

## Important forensic boundary

DFIP does not claim that a web application alone replaces a validated forensic acquisition workstation or every specialist parser. The adapter layer is deliberately isolated so validated versions of The Sleuth Kit/libewf, Plaso, ExifTool, Wireshark/tshark, YARA, Volatility and other approved tooling can be deployed in a controlled forensic worker environment. Original evidence is never intentionally modified by the DFIP analysis layer.

## Integrated forensic tooling

The backend image holds the tools the analysis modules run (`backend/Dockerfile`, `backend/requirements.txt`, exact versions pinned):

- **Disks and file systems:** The Sleuth Kit (pytsk3 in-process, and `mmls`, `fls`, `icat`, `istat`, `blkls`), libewf, libvhdi, libvmdk, libqcow, libbde (BitLocker), libluksde (LUKS), libvshadow (Volume Shadow Copies), libfsntfs (MFT, alternate data streams, USN journal), APFS through the Sleuth Kit.
- **Windows artefacts:** regipy and libregf (registry), libscca (Prefetch), liblnk and libolecf (shortcuts, Jump Lists), libevtx (event logs) with a Sigma-subset rule engine, libesedb (SRUM, Windows Search).
- **Files and content:** libmagic, yara-python, pdftotext, 7-Zip, olefile and defusedxml, an SQLite FTS5 trigram index per evidence item, google-re2.
- **Email, chat and media:** libpff (PST/OST), Python's mailbox and email modules, ExifTool, Pillow, ffmpeg, Tesseract OCR.
- **Malware:** pefile, signify (Authenticode), capa with pinned rules, ClamAV (databases downloaded or added offline), YARA rule sets, VirusTotal lookups (off unless a case turns them on).
- **Networks, phones and memory:** tshark (pcap, pcapng), DFIP's own Android and iOS readers, Volatility 3 (with symbol packs; offline unless `MEMORY_SYMBOL_SERVER` is on).
- **Reports and exports:** ReportLab, pyHanko (PAdES signatures), openpyxl, stix2, case-utils.

No specialist tool is invoked through a shell, and original evidence is never used as a writable destination.

## User interface

One React codebase in `frontend/`, built for two targets:

| | Web portal (`npm run build`) | Desktop app (`npm run build:desktop`) |
|---|---|---|
| Opens on | Public website (`/`): features with screenshots, workflow, evidence integrity, platforms and download, FAQ | The sign-in page |
| After sign-in | The case workspace | The same case workspace, plus workstation details and local hash verification |
| Server | Same origin (nginx proxies `/api`) | Configurable on the sign-in page (default `http://localhost:8000`) |

The workspace is organised around an **active case** (switcher in the top bar). Its home screen, the *case desktop*, shows the evidence with live analysis progress and a tile for every function with live counts: Evidence and Physical evidence; Files, Timeline, Browser history, Email, Chat and cloud, Phones, Network, Pictures and videos, USB devices, Windows activity, Event logs, File system journal, Shadow copies, Linux and macOS, Memory, Computer and users; Indicators, File carving, Found data, Link graph, Case summary and Keyword search; Findings (with peer review), Tagged items, Reports and Chain of custody. Administrators also get Users, Audit log, Hash sets, Malware rules, Retention and System & tools (with the memory symbol packs). Every table exports as CSV or XLSX. Actions a role cannot perform are hidden; the server enforces every permission regardless. Times display in UTC by default (switchable to local time in the top bar).

Development: `npm run dev` (web, port 5173, proxies the API on 8000) or `npm run dev:desktop` (desktop UI in a browser, port 1420).

## DFIP Investigator Desktop

`desktop/` is the Tauri 2 shell that loads the desktop build of the UI in a native Windows window. Its native commands (Rust, `desktop/src-tauri/src/main.rs`) include streaming SHA-256/SHA-512 hashing of local files, used to verify a local copy of an image against the registered evidence without uploading it again. On sign-in the app registers the workstation with the server, which allows `REQUIRE_DESKTOP_FOR_WRITES=true` deployments.

Build the installers with `desktop/scripts/build-windows.ps1` (needs Rust and the Tauri Windows prerequisites; see `desktop/INSTALL.md`), or with only Docker: `sh desktop/scripts/build-windows-docker.sh` (cross-compiles the NSIS installer). Installers in `storage/downloads` are offered on the website (hero and Platforms section), on the web sign-in page and in the web workspace sidebar, each with its SHA-256.
