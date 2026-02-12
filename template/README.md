# MTD Admin Dashboard - Hackathon Demo

## 🚀 Overview
This is a complete Moving Target Defense (MTD) admin dashboard with:
- **Login system** with honeypot redirection
- **AI-powered threat detection** toggle
- **Real-time IP activity logs**
- **Threat alarm system**
- **DBMS backend access**
- **Interactive honeypot environment**

## 📁 Files Included
1. `login.html` - Login page with honeypot redirection
2. `dashboard.html` - Main admin dashboard
3. `honeypot.html` - Honeypot environment for attackers

## 🔐 Login Credentials

### For Legitimate Access (Admin):
- **Username:** `admin`
- **Password:** `mtd2024`

### For Honeypot Demonstration:
- Enter **ANY wrong credentials 3 times** to trigger honeypot redirect

## 🎯 Demo Flow for Judges

### Part 1: Show Normal Operation
1. Open `login.html`
2. Login with correct credentials (admin/mtd2024)
3. You're now in the dashboard - show:
   - Real-time IP logs (all traffic visible)
   - AI Toggle is **ON** (green)
   - Metrics updating in real-time
   - Threats being blocked automatically

### Part 2: Show AI Toggle Impact
1. In the dashboard, **turn OFF the AI toggle**
2. Watch what happens:
   - More threats get through
   - System becomes vulnerable
   - Logs show "AI DISABLED - NOT BLOCKED" messages
3. **Turn AI back ON** to restore protection

### Part 3: Show Threat Alarm
1. With AI enabled, watch for port scanning activity
2. When a scan is detected, you'll see:
   - 🚨 Red alarm banner at the top
   - Flashing red overlay
   - "THREAT DETECTED" message
3. Click "Dismiss" to clear the alarm

### Part 4: Show DBMS Access
1. Scroll to the "Database Management" section
2. The pre-filled query shows recent logs
3. Click **"Execute Query"** to see database results
4. Try custom queries like:
   ```sql
   SELECT * FROM access_logs WHERE status = 'blocked' LIMIT 10;
   ```

### Part 5: Demonstrate Honeypot
1. **Open a new tab** (keep dashboard open)
2. Go to `login.html`
3. Enter **wrong credentials 3 times**:
   - Username: `attacker`
   - Password: `hack123`
4. After 3 failed attempts:
   - See "ACCESS DENIED" animation
   - Auto-redirect to honeypot environment
5. In honeypot, show:
   - Fake terminal capturing "attacker" data
   - Session timer running
   - Packets being "captured"
   - Fingerprints being "collected"
6. **Go back to the dashboard tab**
7. See the honeypot redirect logged in the activity feed!

## 🎨 Key Features to Highlight

### 1. Complete IP Logging
- Every single IP request is logged (legitimate or not)
- Filter by: All Traffic, Legitimate, Threats, Port Scans
- Search by IP address
- Real-time updates

### 2. AI Toggle Demonstration
- Shows the difference WITH and WITHOUT AI protection
- When OFF: More threats succeed
- When ON: AI blocks sophisticated attacks
- Perfect for showing the value of your system!

### 3. Threat Alarm System
- Automatically triggers on port scans and attacks
- Visual and audio-like alerts (red overlay)
- Cannot be missed during demo

### 4. DBMS Backend Access
- Execute SQL queries directly from dashboard
- View logs in database format
- Shows technical depth of your project

### 5. Honeypot Integration
- Attackers who fail login are redirected
- Completely isolated environment
- Logs their activity back to main dashboard

## 🛠️ How to Run

### Option 1: Local File (Easiest)
1. Download all 3 HTML files to the same folder
2. Double-click `login.html`
3. Everything works offline!

### Option 2: Local Server
```bash
# Using Python
python -m http.server 8000

# Then open: http://localhost:8000/login.html
```

### Option 3: Deploy to Web
Use **Netlify** or **GitHub Pages**:
1. Upload all files to a GitHub repo
2. Enable GitHub Pages
3. Share the link with judges!

## 💡 Pro Tips for Demo

1. **Start with AI ON** - Show normal operation first
2. **Turn AI OFF** - Demonstrate vulnerability (mind-blowing moment)
3. **Wait for alarm** - Let a threat trigger the red alarm
4. **Show DBMS** - Execute a query to show technical depth
5. **Trigger honeypot** - In a separate tab, fail login 3 times
6. **Return to dashboard** - Show the honeypot redirect was logged

## 🎤 Talking Points

- "Our MTD system constantly rotates API endpoints"
- "With AI enabled, we detect and block sophisticated attacks"
- "Watch what happens when I disable AI protection..." (toggle OFF)
- "See? Without AI, threats get through. Now watch when I turn it back on..."
- "Every single IP is logged, legitimate or malicious"
- "When an attack is detected, we trigger this alarm" (wait for it)
- "For persistent attackers, we redirect them to our honeypot"
- "We can even query the backend database directly from the dashboard"

## 🏆 Judge Impact Factors

✅ **Real-time visualization** - Everything updates live
✅ **Interactive AI toggle** - Shows clear before/after
✅ **Professional UI** - Clean, modern, SOC-style design
✅ **Security depth** - Honeypot, DBMS, complete logging
✅ **Working demo** - No backend needed, runs instantly

## 🔧 Customization

### Change Login Credentials
Edit `login.html`, line ~200:
```javascript
const CORRECT_USERNAME = 'admin';
const CORRECT_PASSWORD = 'mtd2024';
```

### Adjust Traffic Simulation Speed
Edit `dashboard.html`, last line:
```javascript
setInterval(simulateTraffic, 3000); // Change 3000 to 1000 for faster traffic
```

### Add Your Backend Later
Replace the `simulateTraffic()` function with actual API calls:
```javascript
async function fetchRealData() {
    const response = await fetch('http://your-api:3000/logs');
    const data = await response.json();
    // Update dashboard with real data
}
```

## 📊 What Makes This Different

Most security dashboards just show metrics. This one:
- **Lets judges interact** (toggle AI, run queries)
- **Shows real impact** (AI on vs off comparison)
- **Has a wow factor** (honeypot redirect)
- **Tells a story** (complete security workflow)

## 🎬 30-Second Pitch

"We built a Moving Target Defense system that constantly rotates API endpoints. This admin dashboard shows every IP in real-time. Watch - when I toggle AI off, attacks get through. When it's on, we block them automatically. Persistent attackers? We redirect them to this honeypot where we collect intelligence. Judges can even query our database directly."

---

Good luck at your hackathon! 🚀

**Default Admin Credentials:**
- Username: `admin`
- Password: `mtd2024`
