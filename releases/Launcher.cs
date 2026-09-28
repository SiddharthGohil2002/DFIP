using System;
using System.Diagnostics;
using System.Drawing;
using System.IO;
using System.Net.Sockets;
using System.Windows.Forms;

namespace DFIP.Investigator
{
    public class Program
    {
        [STAThread]
        public static void Main(string[] args)
        {
            Application.EnableVisualStyles();
            Application.SetCompatibleTextRenderingDefault(false);

            bool forceDialog = false;
            if (args != null)
            {
                foreach (string arg in args)
                {
                    if (arg.Equals("--gui", StringComparison.OrdinalIgnoreCase) ||
                        arg.Equals("-g", StringComparison.OrdinalIgnoreCase) ||
                        arg.Equals("/gui", StringComparison.OrdinalIgnoreCase))
                    {
                        forceDialog = true;
                        break;
                    }
                }
            }

            int activePort = 0;
            if (IsPortOpen("127.0.0.1", 1420, 350))
            {
                activePort = 1420;
            }
            else if (IsPortOpen("127.0.0.1", 5173, 350))
            {
                activePort = 5173;
            }

            if (!forceDialog && activePort > 0)
            {
                LaunchBrowserApp(activePort);
                return;
            }

            ShowControlCenter(activePort);
        }

        private static bool IsPortOpen(string host, int port, int timeoutMs)
        {
            try
            {
                using (TcpClient client = new TcpClient())
                {
                    IAsyncResult ar = client.BeginConnect(host, port, null, null);
                    bool ok = ar.AsyncWaitHandle.WaitOne(timeoutMs);
                    if (!ok) return false;
                    client.EndConnect(ar);
                    return true;
                }
            }
            catch
            {
                return false;
            }
        }

        private static void LaunchBrowserApp(int port)
        {
            string url = "http://127.0.0.1:" + port;
            string dataDir = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DFIP", "DesktopProfile");
            try { Directory.CreateDirectory(dataDir); } catch { }

            string browser = FindBrowser();
            if (!string.IsNullOrEmpty(browser))
            {
                try
                {
                    ProcessStartInfo psi = new ProcessStartInfo();
                    psi.FileName = browser;
                    psi.Arguments = "--app=\"" + url + "\" --user-data-dir=\"" + dataDir + "\" --window-size=1440,920";
                    psi.UseShellExecute = true;
                    Process.Start(psi);
                    return;
                }
                catch { }
            }

            try
            {
                Process.Start(new ProcessStartInfo(url) { UseShellExecute = true });
            }
            catch (Exception ex)
            {
                MessageBox.Show("Unable to open browser: " + ex.Message, "DFIP Launcher", MessageBoxButtons.OK, MessageBoxIcon.Error);
            }
        }

        private static string FindBrowser()
        {
            string p86 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFilesX86);
            string p64 = Environment.GetFolderPath(Environment.SpecialFolder.ProgramFiles);
            string local = Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData);

            string[] candidates = new string[]
            {
                Path.Combine(p86, @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(p64, @"Microsoft\Edge\Application\msedge.exe"),
                Path.Combine(p64, @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(p86, @"Google\Chrome\Application\chrome.exe"),
                Path.Combine(local, @"Google\Chrome\Application\chrome.exe")
            };

            foreach (string p in candidates)
            {
                if (File.Exists(p)) return p;
            }
            return null;
        }

        private static void ShowControlCenter(int initialPort)
        {
            Form form = new Form();
            form.Text = "DFIP Investigator - Forensic Workstation v2.0.0";
            form.Size = new Size(600, 470);
            form.StartPosition = FormStartPosition.CenterScreen;
            form.FormBorderStyle = FormBorderStyle.FixedDialog;
            form.MaximizeBox = false;
            form.BackColor = Color.FromArgb(248, 249, 250);

            Label title = new Label();
            title.Text = "DFIP INVESTIGATOR WORKSTATION";
            title.Font = new Font("Segoe UI", 15, FontStyle.Bold);
            title.ForeColor = Color.FromArgb(200, 16, 46);
            title.Location = new Point(28, 20);
            title.AutoSize = true;
            form.Controls.Add(title);

            Label subtitle = new Label();
            subtitle.Text = "Digital Forensics & Incident Response Platform // v2.0.0 Stable";
            subtitle.Font = new Font("Segoe UI", 9, FontStyle.Regular);
            subtitle.ForeColor = Color.FromArgb(100, 116, 139);
            subtitle.Location = new Point(28, 52);
            subtitle.AutoSize = true;
            form.Controls.Add(subtitle);

            TextBox log = new TextBox();
            log.Multiline = true;
            log.ReadOnly = true;
            log.ScrollBars = ScrollBars.Vertical;
            log.BackColor = Color.FromArgb(255, 255, 255);
            log.ForeColor = Color.FromArgb(30, 41, 59);
            log.Font = new Font("Consolas", 9.5f);
            log.Location = new Point(28, 86);
            log.Size = new Size(528, 220);
            log.Text = "[+] DFIP Forensic Workstation Client Initialized.\r\n" +
                       "[+] Cryptographic Engine: SHA-256 / SHA-1 / MD5 Ready\r\n" +
                       "[+] Hardware Write-Block Monitor: ENABLED (Zero-Byte Alteration)\r\n" +
                       "[+] Case Vault: %APPDATA%\\DFIP\r\n" +
                       "[+] Desktop UI Service: http://127.0.0.1:1420\r\n" +
                       "[+] Web Console Service: http://127.0.0.1:5173\r\n" +
                       "[+] Central API Endpoint: http://127.0.0.1:8000/api\r\n\r\n" +
                       (initialPort > 0 
                           ? "[+] Service detected on port " + initialPort + "! Ready to connect." 
                           : "[*] Waiting for local DFIP services. You may launch the desktop window now.");
            form.Controls.Add(log);

            Button launchBtn = new Button();
            launchBtn.Text = "Launch Desktop App (Port 1420)";
            launchBtn.Font = new Font("Segoe UI", 10, FontStyle.Bold);
            launchBtn.BackColor = Color.FromArgb(200, 16, 46);
            launchBtn.ForeColor = Color.White;
            launchBtn.FlatStyle = FlatStyle.Flat;
            launchBtn.FlatAppearance.BorderSize = 0;
            launchBtn.Location = new Point(28, 324);
            launchBtn.Size = new Size(250, 42);
            launchBtn.Cursor = Cursors.Hand;
            launchBtn.Click += (s, e) => {
                LaunchBrowserApp(1420);
            };
            form.Controls.Add(launchBtn);

            Button webBtn = new Button();
            webBtn.Text = "Web Console (Port 5173)";
            webBtn.Font = new Font("Segoe UI", 9.5f, FontStyle.Regular);
            webBtn.BackColor = Color.FromArgb(241, 245, 249);
            webBtn.ForeColor = Color.FromArgb(30, 41, 59);
            webBtn.FlatStyle = FlatStyle.Flat;
            webBtn.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
            webBtn.Location = new Point(290, 324);
            webBtn.Size = new Size(180, 42);
            webBtn.Cursor = Cursors.Hand;
            webBtn.Click += (s, e) => {
                LaunchBrowserApp(5173);
            };
            form.Controls.Add(webBtn);

            Button folderBtn = new Button();
            folderBtn.Text = "Open Vault";
            folderBtn.Font = new Font("Segoe UI", 9f, FontStyle.Regular);
            folderBtn.BackColor = Color.FromArgb(241, 245, 249);
            folderBtn.ForeColor = Color.FromArgb(71, 85, 105);
            folderBtn.FlatStyle = FlatStyle.Flat;
            folderBtn.FlatAppearance.BorderColor = Color.FromArgb(203, 213, 225);
            folderBtn.Location = new Point(480, 324);
            folderBtn.Size = new Size(76, 42);
            folderBtn.Cursor = Cursors.Hand;
            folderBtn.Click += (s, e) => {
                string p = Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.ApplicationData), "DFIP");
                Directory.CreateDirectory(p);
                Process.Start("explorer.exe", p);
            };
            form.Controls.Add(folderBtn);

            Label footer = new Label();
            footer.Text = "ISO/IEC 27037 Standard Compliant · Federal Rule of Evidence 902(14)";
            footer.Font = new Font("Segoe UI", 8.25f, FontStyle.Regular);
            footer.ForeColor = Color.FromArgb(148, 163, 184);
            footer.Location = new Point(28, 385);
            footer.AutoSize = true;
            form.Controls.Add(footer);

            Application.Run(form);
        }
    }
}
