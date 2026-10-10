# Deploying Tripwire to a Debian VM on Google Cloud

Three containers run with Docker Compose:

- **analyzer** opens links in a sandboxed browser and decides the verdict. It publishes no port and
  holds no chat credentials.
- **gateway** talks to iMessage through Photon and calls the analyzer over a private Docker network.
- **caddy** is the only thing on the internet: HTTPS on 80/443 for a free `*.sslip.io` hostname,
  forwarding only the routes a visitor needs. `POST /analyze` is never exposed.

The VM should be used for nothing else: it opens live phishing pages. If the VM has run an earlier
deployment, start at step 0.

Commands marked **laptop** run in Windows PowerShell; commands marked **VM** run over SSH.
Replace `VM_NAME` and `ZONE` with yours.

## 0. Clear any previous deployment (VM; skip if this VM has never run Tripwire)

A previous deployment on the same VM collides with this one in four ways: its Docker network is
also called `tripwire` and uses the same subnet (172.30.0.0/24), its firewall rules name that
subnet, its gateway may still be answering messages on the same Photon project, and its folder may
be the one step 4 wants to clone into. Remove all four before going on.

### 0a. Look first (read-only)

```bash
docker compose ls -a
docker ps -a --format 'table {{.Names}}\t{{.Image}}\t{{.Status}}'
docker network ls
sudo iptables -S DOCKER-USER
sudo iptables -S INPUT | grep -E '172\.30\.0\.|tripwire' || true
systemctl list-unit-files --type=service | grep -i -E 'tripwire|egress' || true
sudo ss -ltnp | grep -E ':(80|443)\b' || true
```

Note the folder in the `CONFIG FILES` column of `docker compose ls -a`: that is the old stack's
folder. Anything else you do not recognise in these lists is not Tripwire's: leave it alone.

### 0b. Shut the old stack down

From the old stack's folder (the one holding its `docker-compose.yml`):

```bash
cd /PATH/TO/OLD/FOLDER
docker compose down --remove-orphans
```

If the folder is gone, use the project name from `docker compose ls -a` instead:
`docker compose -p PROJECT_NAME down --remove-orphans`.

Then remove whatever still sits on the old network, and the network itself:

```bash
docker ps -aq --filter network=tripwire | xargs -r docker rm -f
docker network rm tripwire
```

`No such network` is fine: it means `down` already removed it. If `network rm` says the network
"has active endpoints", something is still attached:
`docker network inspect tripwire --format '{{range .Containers}}{{.Name}} {{end}}'`.

(`down` without `-v` keeps volumes. Old volumes hold nothing this version needs; list them with
`docker volume ls` and remove the ones that belong to the old stack with `docker volume rm NAME`.)

### 0c. Remove the old firewall rules

This deletes only rules that mention the 172.30.0.x network or carry a `tripwire` comment, in the
two chains an egress script would have used. It does not touch Docker's own rules.

```bash
for chain in DOCKER-USER INPUT; do
  sudo iptables -S "$chain" | grep -E '172\.30\.0\.|tripwire' | sed 's/^-A /-D /' | while read -r rule; do
    echo "removing: $rule"
    sudo iptables $rule
  done
done
sudo iptables -S DOCKER-USER
sudo iptables -S INPUT | grep -E '172\.30\.0\.|tripwire' || echo "INPUT: no old rules"
```

Expected: `DOCKER-USER` shows only `-N DOCKER-USER` and `-A DOCKER-USER -j RETURN`, and the INPUT line
says no old rules. If a rule is left (for example a comment with spaces), delete it by number:
`sudo iptables -L DOCKER-USER -n --line-numbers`, then `sudo iptables -D DOCKER-USER N`.

### 0d. Remove whatever re-applies them at boot

```bash
systemctl list-unit-files --type=service | grep -i -E 'tripwire|egress' || true
sudo grep -rIl -i -E 'egress|172\.30\.0\.' /etc/systemd /etc/cron.d /etc/cron.daily /etc/rc.local /etc/iptables 2>/dev/null || true
```

For each service the first command prints (for example `tripwire-egress.service`), look at what it
runs and then remove it:

```bash
systemctl cat NAME.service --no-pager
sudo systemctl disable --now NAME.service
sudo rm -f /etc/systemd/system/NAME.service
sudo systemctl daemon-reload
```

Anything the second command lists (a cron job, `rc.local`, saved iptables rules) is another
persistence mechanism for the old rules: open it, remove the old lines, and save.

### 0e. Move the old folder aside

If the old stack lived in `~/tripwire`, step 4 clones into the same name. Move it instead of
deleting it:

```bash
[ -d ~/tripwire ] && mv ~/tripwire ~/tripwire-previous
```

Its `.env` may hold keys you still want (feed keys, Photon project). Open it with `nano` and copy
the values you need into the new `.env` in step 5; do not `cat` it into a shared terminal. Delete
the folder once the new stack works: `rm -rf ~/tripwire-previous`.

### 0f. Check it is clean

| Check | Expected |
| --- | --- |
| `docker ps -a` | no Tripwire containers |
| `docker network ls` | no network named `tripwire` |
| `sudo iptables -S DOCKER-USER` | only `-N DOCKER-USER` and `-A DOCKER-USER -j RETURN` |
| `sudo iptables -S INPUT \| grep -E '172\.30\.0\.\|tripwire'` | nothing |
| `systemctl list-unit-files \| grep -i -E 'tripwire\|egress'` | nothing |
| `sudo ss -ltnp \| grep -E ':(80\|443)\b'` | nothing (Caddy needs both ports) |
| `ls ~/tripwire` | `No such file or directory` |
| `docker system df` | tells you how much old image space there is; `docker image prune -f` reclaims dangling layers, `docker builder prune -f` the build cache |

Also stop the gateway on your laptop now if it is running: two gateways on one Photon project would
both answer every message.

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

Check first: `docker compose version`. If it prints a version, Docker is installed: skip the Docker
installation below and only make sure the two small tools exist, then go to step 4:

```bash
sudo apt-get update && sudo apt-get install -y git iptables
```

Otherwise install everything:

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

The repository is private, so pick one. The commands below put it in `~/tripwire`, which step 0e
cleared if an older deployment lived there.

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

Before it adds any rule, the script makes sure the kernel really sends traffic between containers
through iptables: it loads the `br_netfilter` module, sets `net.bridge.bridge-nf-call-iptables=1`,
and writes the two files that do the same at boot (`/etc/modules-load.d/br_netfilter.conf` and
`/etc/sysctl.d/99-tripwire-egress.conf`). This matters: on a VM where that module is not loaded,
traffic between containers on the same network skips the firewall entirely, so the analyzer could
reach the gateway and Caddy even with every rule installed (the rules for the internet and the VM
still work, which hides the problem). If the script cannot get the setting to `1` it stops with an
error and installs nothing. If you already set these by hand, it finds them in place.

It prints the rules it added and is safe to run again. The rules are lost on reboot, so keep them
with a systemd unit that re-applies them whenever Docker starts (step 0d removed any older unit
with this name, so this creates a fresh one):

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

**Bridge filtering must be on** (the precondition for the next check):

```bash
cat /proc/sys/net/bridge/bridge-nf-call-iptables
lsmod | grep br_netfilter
cat /etc/modules-load.d/br_netfilter.conf
```

Expected: `1`, a `br_netfilter` line, and `br_netfilter`. If the first command says
`No such file or directory`, the module is not loaded: run `sudo bash deploy/egress-firewall.sh`
again and read what it prints.

**The VM itself and the other containers must be unreachable from the analyzer:**

```bash
docker compose exec analyzer python -c "import urllib.request; urllib.request.urlopen('http://172.30.0.12/', timeout=5)"
docker compose exec analyzer python -c "import socket; socket.create_connection(('$(hostname -I | awk '{print $1}')', 22), timeout=5)"
```

Expected: a timeout error each time. If the first one (Caddy, another container on the same
network) answers, bridge filtering is off even though the rules look installed; go back to the
previous check. After a reboot, run the bridge-filtering check and this one again once: the module,
the sysctl and the rules must all have come back by themselves.

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

**The report link.** The reply ends with `Full report: https://<your-host>.sslip.io/api/report/<id>`.
It is the one tappable link Tripwire sends: everything about the scanned page is defanged. Tap it
(or open it from the laptop) and you get that scan's result as JSON:

```powershell
Invoke-RestMethod https://34-123-45-67.sslip.io/api/report/<id> | Select-Object verdict, score, headline
Invoke-RestMethod https://34-123-45-67.sslip.io/api/report/000000000000    # 404: no such report
```

If the reply has no `Full report` line, the gateway has no `PUBLIC_URL`: `docker compose up -d`
recreates it from `SITE_HOST`. Reports are small JSON files in `data/reports/`; they hold the same
defanged result the reply was built from, and nothing about who asked.

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

## Check Tripwire against live scams (VM only)

`analyzer/live_check.py` takes fresh phishing links from OpenPhish and known-good links from
`analyzer/data/benign.txt`, runs each through the real pipeline, and prints a defanged table. It
**opens live phishing pages**, so it refuses to run unless `TRIPWIRE_EVAL_OK=1` is in the VM's `.env`.
Never set that on a laptop.

Switch it on once, and check the firewall is in place first (expect `7`):

```bash
cd ~/tripwire
sudo iptables -S DOCKER-USER | grep -c tripwire-egress
sed -i 's/^TRIPWIRE_EVAL_OK=.*/TRIPWIRE_EVAL_OK=1/' .env
grep -c '^TRIPWIRE_EVAL_OK=1' .env        # expect 1
docker compose up -d                       # recreates the analyzer with the new value
docker compose ps                          # analyzer: healthy
```

Run the five-scams check (5 live phishing links and 5 known-good links, three at a time; about a
minute):

```bash
docker compose exec analyzer python live_check.py --phish 5 --benign 5
```

How to read it:

- Each link shows its verdict with every signal, and again with the threat-feed hits removed. The
  links come from OpenPhish and Tripwire also asks OpenPhish, so the first column is flattering: the
  **"feeds removed" column is the honest measure** of the page and domain signals.
- Many phishing links are already dead by the time they are opened. A dead page is "couldn't check"
  (or "dangerous" if a feed still lists it). That is correct, not a miss. If most of the five are dead,
  run it again for a different five.
- **"said no red flags (MISSED)"** on a phishing link, and **"FALSE ALARMS"** on a known-good link,
  are the two numbers that matter. Paste either section to whoever is tuning the scoring.
- Add `--seed 7` to repeat exactly the same sample. Screenshots land in `data/live/<timestamp>/`.

**If the log shows `read of screenshot failed after 4.0s`:** the browsers are competing for the VM's
CPU (an `e2-medium` has one sustained vCPU shared by everything). Count them, then try fewer browsers
at once and run the same sample again:

```bash
docker compose logs analyzer | grep -c "read of screenshot failed"
sed -i 's/^TRIPWIRE_BROWSERS=.*/TRIPWIRE_BROWSERS=2/' .env
docker compose up -d
docker compose exec analyzer python live_check.py --phish 5 --benign 5 --seed 3270563943
```

`live_check` prints how many browsers it used and how many scans took over 15 seconds, so two runs
with the same `--seed` compare directly. A single scan from a phone has the VM to itself, so it needs
this far less than the check does.

To forward live scams from your phone instead, print five fresh links (they are **not** defanged:
paste them into the Tripwire chat, never open them):

```bash
docker compose exec analyzer python live_check.py --list 5
```

Copy the screenshots off the VM to look at them (on the VM, then on the laptop):

```bash
LATEST=$(ls -1 data/live | tail -1); sudo tar czf ~/live-$LATEST.tgz -C data/live "$LATEST"; sudo chown "$USER": ~/live-$LATEST.tgz; echo ~/live-$LATEST.tgz
```

```powershell
gcloud compute scp --zone $ZONE "${VM}:live-<that name>.tgz" .
```

Switch the guard off again when you are done: `sed -i 's/^TRIPWIRE_EVAL_OK=.*/TRIPWIRE_EVAL_OK=/' .env`
then `docker compose up -d`.

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
- **Traffic between containers is only filtered when `br_netfilter` is loaded.** Docker normally
  loads it, but some VM images do not. The firewall script handles it and refuses to continue if
  it cannot.
- **DNS is set to 1.1.1.1 and 8.8.8.8** because Google Cloud's default resolver is the metadata
  address, which the firewall blocks.
- **Screenshots and reports pile up** in `./data` and `./data/reports`. A report link stops working
  when its file is deleted, so clear both together:
  `sudo find data -name '*.png' -mtime +7 -delete; sudo find data/reports -name '*.json' -mtime +7 -delete`.
- **The certificate** is issued by Let's Encrypt on first start, which needs port 80 reachable from
  the internet. If `docker compose logs caddy` shows certificate errors, re-check step 1.
