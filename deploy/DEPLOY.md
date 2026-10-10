# Deploying Tripwire to a Debian VM on Google Cloud

Three containers run with Docker Compose:

- **analyzer** opens links in a sandboxed browser and decides the verdict. It publishes no port and
  holds no chat credentials.
- **gateway** talks to iMessage through Photon and calls the analyzer over a private Docker network.
- **caddy** is the only thing on the internet: HTTPS on 80/443 for a free `*.sslip.io` hostname,
  forwarding only the routes a visitor needs. `POST /analyze` is never exposed.

The VM should be used for nothing else: it opens live phishing pages.

Commands marked **laptop** run in Windows PowerShell; commands marked **VM** run over SSH.
Replace `VM_NAME` and `ZONE` with yours.

## 1. Open ports 80 and 443 (laptop, once)

```powershell
$VM = "VM_NAME"; $ZONE = "ZONE"
gcloud compute firewall-rules create tripwire-web --direction=INGRESS --allow=tcp:80,tcp:443 --target-tags=tripwire-web
gcloud compute instances add-tags $VM --zone $ZONE --tags=tripwire-web
```

(If the rule already exists, the first command says so; carry on.) Nothing else needs to be open
inbound: the gateway only makes outbound connections.

## 2. Connect (laptop)

```powershell
gcloud compute ssh $VM --zone $ZONE
```

## 3. Install Docker and iptables (VM, once)

Check first: `docker compose version`. If that works, skip to step 4.

```bash
sudo apt-get update
sudo apt-get install -y ca-certificates curl git iptables
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc
echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | sudo tee /etc/apt/sources.list.d/docker.list >/dev/null
sudo apt-get update
sudo apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
sudo usermod -aG docker "$USER"
```

Log out and back in (so the `docker` group applies), then `docker compose version` should print a version.

## 4. Get the code onto the VM

The repository is private, so pick one.

### Option A: a read-only deploy key (best: updates are `git pull`)

On the VM:

```bash
mkdir -p ~/.ssh && chmod 700 ~/.ssh
ssh-keygen -t ed25519 -f ~/.ssh/tripwire_deploy -N "" -C "tripwire-vm-deploy"
cat ~/.ssh/tripwire_deploy.pub
```

Copy the whole line it prints. In a browser: the repository on GitHub, **Settings**, **Deploy keys**,
**Add deploy key**. Title `tripwire-vm`, paste the line, leave **Allow write access** unchecked,
**Add key**.

Back on the VM, tell SSH to use that key for this repository:

```bash
cat >> ~/.ssh/config <<'EOF'
Host github-tripwire
  HostName github.com
  User git
  IdentityFile ~/.ssh/tripwire_deploy
  IdentitiesOnly yes
EOF
chmod 600 ~/.ssh/config
ssh -T git@github-tripwire
```

The first time, SSH asks whether to trust github.com. Compare the fingerprint it shows with the ones
on GitHub's page "GitHub's SSH key fingerprints" before typing `yes`. Expected: "Hi ...! You've
successfully authenticated, but GitHub does not provide shell access."

Then clone (use your repository's path):

```bash
cd ~
git clone git@github-tripwire:OWNER/REPO.git tripwire
cd tripwire
```

### Option B: copy it from the laptop (no GitHub setup)

On the laptop, from the repository root. This packs only committed files, so commit first, and
`.env` never travels:

```powershell
git archive --format=tar.gz -o "$env:TEMP\tripwire.tgz" HEAD
gcloud compute scp "$env:TEMP\tripwire.tgz" "${VM}:~/tripwire.tgz" --zone $ZONE
```

On the VM:

```bash
mkdir -p ~/tripwire && tar xzf ~/tripwire.tgz -C ~/tripwire
cd ~/tripwire
```

To update later, repeat the three commands (the `.env` and `data/` on the VM are kept).

## 5. Create the .env on the VM

Secrets are typed on the VM and never leave it.

```bash
cd ~/tripwire
cp .env.example .env
nano .env        # fill in the Photon and feed keys; Ctrl+O, Enter, Ctrl+X to save
chmod 600 .env
```

Set the public hostname from the VM's own external address:

```bash
IP=$(curl -s -H "Metadata-Flavor: Google" "http://metadata.google.internal/computeMetadata/v1/instance/network-interfaces/0/access-configs/0/external-ip")
sed -i "s|^SITE_HOST=.*|SITE_HOST=$(echo "$IP" | tr . -).sslip.io|" .env
grep '^SITE_HOST' .env
```

Expected, for example: `SITE_HOST=34-123-45-67.sslip.io`.

> Do not paste the output of `docker compose config`: it prints the contents of `.env`. To only
> validate the file, use `docker compose config --quiet`.

**Stop the gateway on your laptop first.** Two gateways on the same Photon project would both
answer every message.

## 6. Give the analyzer its data folder

Screenshots are saved in `./data`. The analyzer's user has the fixed id 10001:

```bash
mkdir -p data && sudo chown 10001:10001 data
```

## 7. Install the egress firewall (VM, once)

This is the network-level protection. Whatever a hostile page makes the browser try, the kernel
drops packets from the analyzer to the cloud metadata server, any private address, the other
containers, and the VM itself.

```bash
sudo bash deploy/egress-firewall.sh
```

It prints the rules it added and is safe to run again. The rules are lost on reboot, so keep them
with a systemd unit that re-applies them whenever Docker starts:

```bash
sudo tee /etc/systemd/system/tripwire-egress.service >/dev/null <<EOF
[Unit]
Description=Tripwire egress firewall
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/bash $HOME/tripwire/deploy/egress-firewall.sh

[Install]
WantedBy=multi-user.target
EOF
sudo systemctl daemon-reload
sudo systemctl enable --now tripwire-egress.service
systemctl status tripwire-egress.service --no-pager
```

## 8. Build and start

```bash
docker compose up -d --build
docker compose ps
```

The first build downloads about 3 GB and takes a few minutes. Expected: three services `Up`, the
analyzer `(healthy)`.

```bash
docker compose logs --tail 40 gateway
```

Expected: `Tripwire gateway up. Providers started: imessage`. If it says "No chat provider to start",
the two `SPECTRUM_` values in `.env` are empty; fix `.env`, then `docker compose up -d`.

## 9. Prove it works

Run these from `~/tripwire` on the VM.

**The metadata server must be unreachable** (waits about 5 seconds, then fails):

```bash
docker compose exec analyzer python -c "import urllib.request; urllib.request.urlopen('http://169.254.169.254/', timeout=5)"
```

Expected: a timeout error. If it prints page content, the firewall is not working.

**The VM itself and the other containers must be unreachable from the analyzer:**

```bash
docker compose exec analyzer python -c "import urllib.request; urllib.request.urlopen('http://172.30.0.12/', timeout=5)"
docker compose exec analyzer python -c "import socket; socket.create_connection(('$(hostname -I | awk '{print $1}')', 22), timeout=5)"
```

Expected: a timeout error each time.

**Normal internet access must still work:**

```bash
docker compose exec analyzer python -c "import urllib.request; print(urllib.request.urlopen('https://example.com', timeout=10).status)"
```

Expected: `200`.

**The gateway must still reach the analyzer, and the analyzer must scan:**

```bash
docker compose exec gateway node -e "fetch('http://analyzer:8001/health').then(r => r.text()).then(console.log)"
docker compose exec gateway node -e "fetch('http://analyzer:8001/analyze',{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({urls:['https://example.com']})}).then(r => r.json()).then(j => console.log(j.verdict, j.screenshot_url))"
```

Expected: `{"ok":true}`, then `unscored /shots/<id>.png`. If the second one reports a browser failure,
see "If Chromium will not start" below.

**From your laptop** (replace the hostname with yours; the id is from the line above):

```powershell
Invoke-WebRequest https://34-123-45-67.sslip.io/shots/<id>.png -OutFile $env:TEMP\shot.png; (Get-Item $env:TEMP\shot.png).Length
try { Invoke-RestMethod -Method Post https://34-123-45-67.sslip.io/analyze -ContentType 'application/json' -Body '{"urls":["https://example.com"]}' } catch { $_.Exception.Response.StatusCode.value__ }
```

Expected: a file size, then `404` (the analyze endpoint is not on the internet).

**From your phone**, with the laptop gateway stopped: text the Photon line a benign link such as
`https://example.com`. Close the laptop: it must still answer.

## Updating

After you commit and push from the laptop (Option A), or repeat the Option B copy:

```bash
cd ~/tripwire
git pull
docker compose up -d --build
docker image prune -f
```

If `deploy/egress-firewall.sh` or the network section of `docker-compose.yml` changed, also run
`sudo bash deploy/egress-firewall.sh`. If only `.env` changed, `docker compose up -d` is enough.

## Everyday commands

```bash
docker compose logs -f gateway      # Ctrl+C stops following
docker compose logs -f analyzer
docker compose restart gateway
docker compose down                 # stop and remove containers (data/ and the certificate are kept)
docker stats --no-stream            # memory use; the analyzer is capped at 3 GB
sudo iptables -L DOCKER-USER -n -v --line-numbers   # the DROP counters rise when something is blocked
```

## If Chromium will not start

The analyzer drops all Linux capabilities and sets `no-new-privileges`. If the scan fails with a
browser launch error, remove those two lines (`cap_drop` and `security_opt`) from the `analyzer`
service in `docker-compose.yml`, run `docker compose up -d`, and tell whoever maintains this so the
reason is recorded.

## Good to know

- **The browser runs without Chromium's own sandbox** (Playwright's default in containers). The
  containment is the container itself, the unprivileged user, dropped capabilities, the 3 GB limit
  and the egress firewall, so do not skip step 7.
- **DNS is set to 1.1.1.1 and 8.8.8.8** because Google Cloud's default resolver is the metadata
  address, which the firewall blocks.
- **Screenshots pile up** in `./data`. Clear old ones with
  `sudo find data -name '*.png' -mtime +7 -delete`.
- **The certificate** is issued by Let's Encrypt on first start, which needs port 80 reachable from
  the internet. If `docker compose logs caddy` shows certificate errors, re-check step 1.
