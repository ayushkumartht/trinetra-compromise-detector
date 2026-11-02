<!-- group: Hinglish guide -->
# Basics se samjho: pura topic + pura prototype

> Ye file un logon ke liye hai jinhe **kuch bhi nahi pata**. Hum bilkul zero se shuru karenge: network kya hai, hacking kya hai, IoC kya hai, AI/ML kya hai. Phir dekhenge ki **humara prototype (TRINETRA)** kya karta hai, kaise karta hai, aur judges ke saamne kaise samjhana hai.
>
> **Time kam hai?** Sirf **Part 0** (5 minute) padh lo. Poora padhoge to project ka har hissa samajh aa jayega.

---

## Part 0 · 5 minute mein pura project

**Topic:** Ek AI/ML tool banana jo bataye ki koi **computer (system), firewall, router ya poora network hack (compromised) ho chuka hai ya nahi**, aur ye kaam **IoC ke bina** kare.

**IoC kya hai?** Hacker ke pehle se jaane-pehchaane nishaan, jaise malware file ka fingerprint (hash), hacker ka IP address ya domain. Problem ye hai ki **naye hacker ke nishaan kisi list mein hote hi nahi**.

**Humara idea:** Hacker ka *chehra* mat dhoondo, uska **vyavhaar (behaviour)** dekho. Har device pehle seekhta hai ki woh normally kaisa behave karta hai. Phir jab woh apne normal se alag kaam kare (naye anjaan server se baat, raat ko config badalna, logging band karna), to tool pakad leta hai.

**Prototype ka naam:** **TRINETRA** (Shiv ki teesri aankh, jo bina dikhe bhi dekh leti hai).

**Kaise kaam karta hai (5 step):**

```text
 1. DATA          →  2. FEATURES         →  3. 8 DETECTORS     →  4. FAISLA               →  5. REPORT
 har device se       har 15 min ka          8 alag "jasoos"       sabki raay jodo,          website pe
 logs, connections,  "report card"          apne-apne tareeke     lagataar shak ho aur     CLEAN / SUSPICIOUS /
 config, logins      (28 numbers)           se shak karte hain    2 alag sabooth hon       COMPROMISED
```

**Result (test pe):** 7 mein se 7 hacked devices pakde gaye. 15 clean devices mein se ek ko bhi galti se "hacked" nahi bola. Pakadne ka median (beech wala) time 30 minute tha.

**Base:** Humne **Slips** naam ka ek open-source research tool liya (Czech Technical University, Prague) aur uske upar ye sab banaya.

**Website ke 3 hisse:** `/` landing page (presentation), `/console` (asli tool), `/docs` (documentation).

---

## Part 1 · Network ki ABC

### 1.1 Network kya hota hai?

Socho ek **society** hai:

```text
   SOCIETY (company ka network)
   ┌──────────────────────────────────────────────────────────┐
   │  🏠 ghar = computers (laptop, server)                      │
   │  🛣️ society ki sadkein = network ke wires / WiFi            │
   │  🚦 traffic police = ROUTER (raasta batata hai)            │
   │  💂 main gate ka guard = FIREWALL (kaun andar/bahar jaye)   │
   │  📹 CCTV camera = network SENSOR (sab kuch dekhta hai)      │
   └──────────────────────────────────────────────────────────┘
                     │ main gate
                     ▼
               🌍 INTERNET (bahar ki duniya)
```

| Cheez | Simple matlab | Example |
|---|---|---|
| **System / Host** | koi bhi computer | employee ka laptop (workstation), file server, database server |
| **Server** | woh computer jo dusron ko service deta hai | file server (files rakhta hai), web server (website) |
| **Router** | data ko sahi raste bhejta hai, jaise post office | Cisco router |
| **Firewall** | security guard: rules ke hisaab se traffic allow/block karta hai | FortiGate, Palo Alto |
| **Network** | ye sab devices mil kar | poore office ka LAN |

### 1.2 Kuch zaroori shabd

| Shabd | Simple matlab |
|---|---|
| **IP address** | computer ka "ghar ka pata", jaise `10.0.1.13`. `10.x.x.x` / `192.168.x.x` = andar ke (internal), baaki = internet ke |
| **Port** | ghar ke alag-alag darwaze. 443 = website (HTTPS), 445 = file sharing, 3389 = remote desktop, 22 = SSH, 53 = DNS |
| **Connection / Flow** | ek baat-cheet: "kisne kisse, kis darwaze pe, kitna data bheja" |
| **DNS** | phone book: `google.com` → IP address |
| **Log** | device ki diary, jaise "10:05 user ne login kiya", "10:07 service start hui" |
| **Syslog** | routers/firewalls apni diary is format mein bhejte hain |
| **Config (configuration)** | router/firewall ki **rule-book**, jaise "kaun admin hai, kaunsa traffic allow hai, logs kahan bhejne hain" |
| **Process** | computer pe chalta hua program. **Parent → child** = kis program ne kis program ko chalaya (jaise `explorer → chrome`) |
| **Admin** | jiske paas device ko badalne ki power hai |

---

## Part 2 · Hacking (compromise) kya hai?

### 2.1 "Compromised" ka matlab

Jab hacker kisi device mein ghus kar **uska control le leta hai**, to woh device **compromised** hai. Device bahar se normal dikhta hai, lekin andar hacker baitha hai: data chura raha hai, dusre computers pe ja raha hai, ya chhupa hua intezaar kar raha hai.

### 2.2 Hacker kya-kya karta hai? (attack ki kahani)

Har hacker, chahe uska tool kuch bhi ho, ye kaam **karne pe majboor** hai:

```text
 1. GHUSNA            → email attachment khola, ya weak password
 2. APNE BOSS SE BAAT → hacked computer baar-baar hacker ke server ko "ping" karta hai   (Command & Control / C2)
 3. TIKE RAHNA        → nayi admin ID, naya service, naya rule                          (Persistence)
 4. CHHUPNA           → logs band karna, logs delete karna                               (Defense Evasion)
 5. IDHAR-UDHAR DEKHNA → network mein kaun-kaun hai, scan karna                          (Discovery)
 6. PASSWORD CHURANA  → baar-baar password try karna                                     (Credential Access)
 7. AAGE BADHNA       → ek computer se dusre computer pe jaana                           (Lateral Movement)
 8. DATA BAHAR BHEJNA → files chupke se internet pe bhejna                               (Exfiltration)
```

Ye stages ek famous list mein likhe hain jise **MITRE ATT&CK** kehte hain. Ye hackers ke tareekon ki ek encyclopedia hai, jo poori duniya use karti hai. Har stage ko **tactic** kehte hain (jaise "Persistence"), aur har tareeke ka ek code hota hai, jaise **T1136 = nayi account banana**.

> **Key insight:** hacker ka *tool* naya ho sakta hai, lekin use ye *kaam* karne hi padenge. Aur ye kaam **dikhte** hain.

### 2.3 Routers aur firewalls kyun khaas hain?

- Laptops pe antivirus/EDR chal sakta hai, lekin **routers aur firewalls pe nahi**.
- Isliye bade hackers (sarkari level ke groups) aajkal **routers, firewalls aur VPN** ko target karte hain. Unke real examples: **Volt Typhoon** (2024), **ArcaneDoor** (Cisco firewalls, 2024), **COATHANGER** (FortiGate, 2024), aur 2025 mein **CISA ED 25-03**, jismein US sarkar ko Cisco devices ki memory dump lene ka order dena pada.
- Ek hacked router poore office ka traffic dekh sakta hai, chupke se copy kar sakta hai (mirroring), aur kisi ko pata bhi nahi chalta.

---

## Part 3 · IoC kya hai, aur wo kaafi kyun nahi?

### 3.1 IoC = Indicator of Compromise

**Analogy:** Police ke paas criminals ki **photo list** hai. Jo chehra list se match kare, use pakad lo.

Computer duniya mein ye "photos" hain:

| IoC type | Example |
|---|---|
| File hash (fingerprint) | `e3b0c442...` = ek known malware |
| Bura IP address | `185.x.x.x` = hacker ka known server |
| Bura domain | `evil-update.com` |
| YARA rule | malware ka pattern |

Antivirus aur zyaadatar security tools aise hi kaam karte hain.

### 3.2 Problem

| Problem | Simple misaal |
|---|---|
| **Naya criminal** list mein nahi hota | zero-day attack: kisi ko pata hi nahi ki ye malware hai |
| **List late aati hai** | IoC tab banta hai jab koi attack ko analyse kar chuka ho, yaani **hafton baad** |
| **Bhes badalna aasaan hai** | hacker ₹100 mein naya IP / domain le leta hai |
| **"Ghar ke auzaar"** (Living off the Land) | hacker Windows ke apne tools (PowerShell, WMI) aur chori ke asli password use karta hai, to koi malware file hai hi nahi jise match karein |

### 3.3 To solution kya hai? **Behaviour dekho**

**Analogy 1: Credit card company.** Aapka card roz ₹500 ki chai/khana pe chalta hai. Ek din raat 3 baje kisi dusre desh mein ₹2 lakh ka kharcha hota hai. Company ko chor ki *photo* nahi chahiye, use pata hai ki ye **aapka normal nahi hai**, aur woh call kar leti hai.

**Analogy 2: Society ka watchman.** Watchman jaanta hai ki Sharma ji roz 9 baje office jaate hain. Agar unke ghar se raat 2 baje koi bada bag le ke nikle, to watchman ko shak hoga, chahe us aadmi ki photo kisi list mein na ho.

**Yahi humara approach hai:** har device ka **normal behaviour seekho**, aur jab woh **apne normal se alag** kaam kare, to pakdo. Ise **anomaly detection** kehte hain.

---

## Part 4 · AI / ML ki ABC (sirf utna jitna chahiye)

### 4.1 Machine Learning kya hai?

Computer ko **rules likh ke dene ki jagah, examples dikha ke seekhne dena**.

- Bachche ko 100 billi ki photos dikhao, phir woh nayi billi pehchaan lega.
- Model ko 4 din ka **normal** network data dikhao, phir woh "ajeeb" cheez pehchaan lega.

### 4.2 Do tarah ki learning

| Type | Kaise | Humare kaam ka? |
|---|---|---|
| **Supervised** | "ye attack hai, ye normal hai", dono ke labelled examples chahiye | ❌ naye attacks ke examples hote hi nahi |
| **Unsupervised** | sirf **normal** data dikhao; jo normal jaisa na ho = ajeeb | ✅ **humara approach** |

Isliye humein hacker ka koi example nahi chahiye. Ye **IoC-free** hone ka asli raaz hai.

### 4.3 Kuch ML words

| Shabd | Matlab |
|---|---|
| **Feature** | ek number jo behaviour batata hai, jaise "is 15 minute mein kitne connections hue" |
| **Model** | seekhi hui cheez (formula/program) jo naye data ko judge karti hai |
| **Training / Baseline** | seekhne ka time. Humare test mein pehle **4 din** |
| **Score** | "kitna ajeeb hai" ka number |
| **Threshold** | kitna ajeeb hone pe alarm bajaye |

### 4.4 Do tarah ki galti (bahut important)

| Galti | Matlab | Nuksaan |
|---|---|---|
| **False Positive (false alarm)** | device theek tha, tool ne bola hacked | team pareshaan; dheere-dheere sab alarms ignore karne lagte hain |
| **False Negative (miss)** | device hacked tha, tool ne bola theek | hacker aaram se kaam karta raha |

**Car alarm ki misaal:** jo car alarm har billi pe bajta hai, uspe koi dhyan nahi deta. Isliye problem statement mein likha hai: *"minimise false alarms"*. Ye **sabse bada challenge** hai.

**Measure kaise karte hain:**
- **Precision** = jitne ko "hacked" bola, unmein se kitne sach mein hacked the. Isse false alarm ka pata chalta hai.
- **Recall** = jitne asal mein hacked the, unmein se kitne pakde. Isse miss ka pata chalta hai.
- Humara result: **Precision 100%, Recall 100%** (test data pe).

---

## Part 5 · Problem statement ko simple mein todna

> *Develop an AI/ML tool to detect whether a system / firewall / router / network is compromised. Don't rely only on IoCs.*

Judges 4 cheezon pe number denge:

| Point | Simple matlab | Humara jawab (ek line) |
|---|---|---|
| **(a) Innovation & ruggedness** | kya naya hai? hacker ise aasaani se bewakoof bana sakta hai? | 8 alag detectors + statistics se fusion + "2 alag sabooth" ka rule. Hacker ko ek saath 8 jagah chhupna padega |
| **(b) Utility across devices** | sirf laptop nahi, router/firewall/network sab pe chale? | ek hi engine chaaron pe chalta hai, aur chaaron pe test kiya |
| **(c) Easy deployment & reporting** | lagana aasaan? result samajh aata hai? | ek command se chalta hai, bina internet. Website pe har device ki report aur SIEM export |
| **(d) Minimise false alarms** | faltu alarm kam? | 8 layers ki suraksha; patch / planned change jaise traps pe koi galat alarm nahi |

---

## Part 6 · TRINETRA: humara prototype

### 6.1 Ye bana kis se hai?

| Cheez | Kya hai |
|---|---|
| **Slips** | Stratosphere Lab (CTU Prague) ka open-source network IPS. Ye network traffic dekh ke behaviour se attacks pakadta hai. **Humara base** yahi hai |
| **Python** | engine ki language |
| **numpy, scipy, scikit-learn** | maths aur ML libraries (Isolation Forest, neural network) |
| **Flask** | Python ka chhota web server, jo website chalata hai |
| **HTML / CSS / JavaScript** | website (landing, console, docs) |
| **marked, mermaid** | docs site pe Markdown aur diagrams dikhane ke liye. Ye project ke andar hi rakhe hain, internet nahi chahiye |

**Slips aur humara rishta:** Slips sirf **network traffic** dekhta hai aur **IP address** ke hisaab se sochta hai. Humne usmein ek **naya module** joda aur upar ek **engine** banaya, jo **devices** (router, firewall, laptop, network) ke hisaab se sochta hai, aur routers/firewalls ke **config aur logs** bhi samajhta hai.

> Slips ko chalne ke liye Linux + Redis chahiye. Aapke laptop pe Windows hai aur Docker nahi hai, isliye engine aur website **Windows pe alag se** chalti hai. Slips module Linux/Docker pe chalega.

### 6.2 Big picture

```text
 ┌─────────────────────────── DATA KAHAN SE AATA HAI ───────────────────────────┐
 │  Slips / Zeek          Routers & Firewalls            Computers               │
 │  (network traffic,     (logs, config file,            (logins, programs,      │
 │   DNS, Slips alerts)    admin logins)                  CPU)                   │
 └───────────┬─────────────────────┬─────────────────────────┬──────────────────┘
             └──────────────┬──────┴─────────────────────────┘
                            ▼
              ① UBT: sabko ek hi "bhasha" mein badlo
                            ▼
              ② har device ka har 15-min ka REPORT CARD (28 numbers)
                            ▼
              ③ 8 DETECTORS (8 jasoos) → har ek ka "kitna ajeeb" score
                            ▼
              ④ FAISLA: score ko probability banao → jodo → lagataar? → 2 sabooth?
                            ▼
              ⑤ VERDICT + REPORT:  ✓ CLEAN   ! SUSPICIOUS   ✕ COMPROMISED
                            ▼
              Website (console) · forensic report · SIEM export
```

Ab har step ko ek-ek karke samajhte hain.

---

## Part 7 · Step ① Data: sabko ek bhasha mein (UBT)

Problem ye hai ki router ki language alag hai, firewall ki alag, laptop ki alag. Agar har ek ke liye alag tool banayein, to 4 tool ban jayenge.

**Solution:** sabko ek common format mein badlo. Ise humne naam diya **UBT (Unified Behavioural Telemetry)**. Har cheez ek **event** hai, aur event sirf 8 tarah ke hote hain:

| Event | Matlab | Example |
|---|---|---|
| `flow` | ek connection | WS-03 ne 185.x.x.x ke port 443 pe 600 bytes bheje |
| `dns` | naam dhoondha | `abcxyz.t.sync-cdn.org` |
| `auth` | login try | user `admin`, from `92.1.2.3`, **fail** |
| `proc` | program chala | `doc_viewer → script_host` |
| `log` | diary ki ek line (type) | `aaa_login_fail`, `config_enter` |
| `config` | poori rule-book (naya version) | router ki config file |
| `resource` | CPU / memory | CPU 85% |
| `alert` | Slips ki raay | "high: C&C channel detected" |

Har event ek line hoti hai:

```json
{"ts": 1791243000, "device": "RTR-EDGE", "kind": "auth", "user": "admin", "src": "92.1.2.3", "ok": false}
```

Isse **ek hi engine chaaron device types pe chal jaata hai**. Jo cheez kisi device pe hoti hi nahi (jaise router pe "program chala"), wo bas zero rehti hai. Ye point **(b) utility across devices** ka jawab hai.

**Adapters:** asli duniya ke formats (Slips output, Zeek logs, Cisco/FortiGate syslog, config backup files) ko UBT mein badalne wale chhote converters. Ye `adapters.py` file mein hain.

---

## Part 8 · Step ② Features: har 15 minute ka report card

Har device ke har **15 minute** ko hum **28 numbers** mein badalte hain, jaise school ka report card.

Kuch examples:

| Feature | Matlab | Hacker se kya rishta |
|---|---|---|
| connections | kitne connections hue | – (busy hona galat nahi) |
| bytes sent to Internet | bahar kitna data gaya | zyada = data chori (**Exfiltration**) |
| never-seen destinations | kitne **naye** anjaan servers se baat ki | hacker ka server (**C2**) |
| new internal connections | andar ke kis naye computer se baat ki | **Lateral Movement** |
| internal hosts contacted / failed connections | kitne andar ke computers ko "khatkhataya" | scanning (**Discovery**) |
| DNS name randomness | domain naam kitna random hai (`x7k2q9...`) | DNS tunnel (**C2 / Exfiltration**) |
| failed logins | kitne login fail hue | password chori ki koshish (**Credential Access**) |
| new user@source logins | kaun **pehli baar** kahan se login hua | chori ka password (**Lateral Movement**) |
| never-seen process chains | kaunsa program pehli baar kisne chalaya | malware chala (**Execution**) |
| log messages | diary mein kitni lines | **kam** ho jaayein = logging band (**Defense Evasion**) |
| CPU / memory | load | – |

Saath mein **time ka context** bhi hota hai, yaani din ka kaunsa samay hai aur working hours hain ya nahi, kyunki raat 2 baje ka traffic aur din 11 baje ka traffic alag hota hai.

### 8.1 "Novelty": pehli baar dekha

Har device ek **register** rakhta hai: maine ab tak kis-kis server se baat ki, kis-kis ne mujhpe login kiya, kaun-kaun se programs chale. Har 15 minute mein check hota hai ki **kya naya hai**.

> Watchman ka register: "ye aadmi pehli baar aaya hai."

### 8.2 Fleet consensus: sab ek saath badle = normal

**Problem:** Windows update aata hai, to **saare 16 computers** ek saath naye update server se baat karte hain, naya installer chalta hai, aur naya log aata hai. Har computer ko akele dekho to lagega ki sab hack ho gaye!

**Solution:** agar koi "nayi cheez" **ek hi device type ke kam se kam 20% devices (minimum 3) pe ek saath** (1 ghante ke andar) dikhe, to woh **company-wide normal change** hai, hacker nahi.

> Hacker shuruaat mein 1-2 computers pakadta hai, poori company ek saath nahi. IT team ka update poori company pe ek saath aata hai.

**Asar:** ye ek rule hata do, to test mein **13 clean computers pe galat alarm** aate hain. Rule ke saath sirf **2** (aur woh bhi sirf "suspicious", "hacked" nahi).

Isme ek **30 minute ka look-ahead** bhi hai: tool 30 minute aage dekh leta hai ki update aur computers pe bhi aaya ya nahi, phir faisla karta hai.

### 8.3 Har device apni hi scale pe

File server roz GBs bhejta hai, router sirf KBs. Isliye har number ko **us device ke apne normal** se compare karte hain ("apne median se kitna door"). Isse saare routers ek saath ek model se seekh sakte hain, chahe har router ka size alag ho (**peer pooling**).

---

## Part 9 · Step ③ Aath detectors (8 jasoos)

Ek jasoos sab kuch nahi dekh sakta, isliye humne **8 alag jasoos** rakhe. Har ek alag cheez dekhta hai:

```text
         ┌─────────────── 28 numbers (report card) wale ───────────────┐
 D1  Robust deviation   "aaj ka din mere normal din se kitna alag hai?"
 D2  Isolation Forest   "kya ye window bheed mein turant alag dikhti hai?"
 D3  Autoencoder        "kya main ise 'normal' jaisa dobara bana paata hoon?"
         ┌─────────────── raw events wale ─────────────────────────────┐
 D4  Log grammar        "kya router/firewall ki diary ka sentence ajeeb hai?"
 D5  Beaconing          "kya koi ghadi ki tarah regular anjaan server ko call kar raha hai?"
 D6  Graph rarity       "kya koi naye raste (kabhi use na hue darwaze) se andar ja raha hai?"
 D7  Config semantics   "rule-book mein KYA badla, KISNE, KAB, KAHAN se?"
 D8  Slips evidence     "Slips ki apni raay kya hai?"
```

### D1 · Robust deviation: "apne aap se compare"
Aapka normal temperature 98.6°F hai. Aaj 103°F hai, to ye **aapke normal se** bahut door hai. Hum har feature ke liye dekhte hain ki woh device ke normal se kitna door hai, aur sabse zyada door wale 3 features ka average lete hain. Report mein yahi dikhta hai: *"never-seen process chains: 4, normal 0"*.

### D2 · Isolation Forest: "20 sawaalon ka khel"
Bheed mein ek normal aadmi ko alag karne ke liye bahut sawaal poochne padte hain ("lamba hai? chashma hai? ..."). Lekin jo aadmi sir pe matka rakh ke khada hai, wo **2 sawaal mein alag** ho jaata hai. Isolation Forest yahi karta hai: jo window bahut jaldi "alag" ho jaaye, wo ajeeb hai. Ek model har device type ke saare devices se seekhta hai.

### D3 · Autoencoder: "copy karne wala student"
Ek chhota neural network jise sirf **normal** data ki "photocopy" banana sikhaya gaya hai. Normal cheez ki copy achhi banti hai. Ajeeb cheez ki copy kharab banti hai, aur **copy mein jitni galti, utna ajeeb**. Ye un combinations ko pakadta hai jo akele-akele normal lagte hain, jaise normal volume lekin galat time pe.

### D4 · Log grammar: "diary ka grammar"
Router ki diary roz kuch aisi hoti hai: `snmp_poll → if_counter → ospf_hello → ...`. Model seekhta hai ki kaunsa word kiske baad aata hai (DeepLog jaisa idea). Raat 11:40 ko diary mein ye aaya:

```text
login_fail → login_fail → … (6 baar) → login_ok → config_enter → … → config_exit → logging_host_removed
```

Ye "sentence" pehle kabhi nahi likha gaya, isliye **bahut surprise** hua.

### D5 · Beaconing: "ghadi jaisi regular call"
Hacked computer har ~75 second pe hacker ke server ko "main zinda hoon" bolta hai. Insaan aise browse nahi karta, insaan random hota hai. Detector dekhta hai ki kisi **anjaan bahari server** ko pichhle 3 ghante mein kam se kam 8 baar contact kiya gaya ho, aur beech ka gap **almost barabar** ho (thoda jitter chalega).

- Hacker: 75s ±15% → **regular** → pakda
- Insaan ka browsing: random gaps → nahi pakda
- NTP / Windows telemetry jaisi achhi regular cheezein baseline mein seekh li jaati hain, to unpe alarm nahi aata

### D6 · Graph rarity: "naya raasta"
Office ka ek naksha banta hai ki kaun kisse kis darwaze pe baat karta hai. Agar WS-03 achanak file server ke **5985 (WinRM, remote control)** darwaze pe jaata hai, jahan **kabhi koi nahi gaya**, to ye bada shak hai (**lateral movement**). Agar ek computer 10+ naye andar ke computers ko khatkhataye, to ye **scanning (Discovery)** hai.

### D7 · Config semantics: "rule-book mein kya badla"
Router/firewall ki config file ke har naye version ko pichhle version se compare karte hain. Har badli line ka **risk** dekhte hain:

| Badlaav | Risk |
|---|---|
| naya admin user bana | 4 |
| "permit any" (sabko andar aane do) rule | 4 |
| tunnel bana (GRE/IPsec bahar ki taraf) | 4 |
| traffic mirroring (sab traffic ki copy) | 4 |
| **logging hata di** | 5 |
| management bahar se khula (`api-access any`, telnet) | 3 |
| route badla | 1.5 |
| koi aur line | 0.3 |

Phir **context** se guna (multiply) karte hain:
- **Maintenance window** (raat 1-3 baje, planned time) mein **jaana-pehchaana admin** ne badla → × 0.3 (planned kaam)
- Window ke **bahar** → × 1.5
- **Anjaan aadmi** ne badla → × 1.5

**Asli examples (humare test se):**

```text
RTR-EDGE (hack):  naya user + tunnel + mirror + logging hataya = 4+4+4+5 = 17
                  raat 11:40 (window ke bahar) ×1.5, internet ka anjaan IP ×1.5   →  17 × 2.25 = 38.25  🔴

RTR-CORE (planned): route + ek line = 1.5 + 0.3 = 1.8
                  raat 1:30 window mein, known admin "netadmin" ×0.3             →  1.8 × 0.3 = 0.54  🟢
```

Isse **"kya badla" + "kisne, kab, kahan se"** dono milke faisla karte hain.

### D8 · Slips evidence: "Slips ki raay"
Slips ke apne ~30 detection modules jo pakadte hain (scan, C&C, etc.), wo bhi ek vote ban jaata hai: `severity × confidence`.

> **Akela koi jasoos kaafi nahi:** test mein Isolation Forest akela 7 mein se sirf **1** pakad paya. Config detector akela bhi sirf **1** (kyunki wo sirf router/firewall dekhta hai). Autoencoder akela 7 pakadta hai lekin 1 clean device ko galti se "hacked" bol deta hai. **Sab milke:** 7/7, 0 galat, 30 min.

---

## Part 10 · Step ④ Faisla: jasooson ki raay kaise jodein?

Ye sabse "smart" hissa hai. 4 chhote kadam hain.

### 10.1 Calibration: sabko ek scale pe laana

Har jasoos ka score alag scale pe hota hai: kisi ka 0-1, kisi ka 0-40. Jaise ek exam 50 marks ka ho aur ek 200 ka, to seedha compare nahi kar sakte. Isliye **percentile** banate hain.

Har score ko badalte hain is sawaal mein: *"agar sab normal hota, to itna ajeeb (ya isse zyada) window kitni baar dikhta?"* Ise **p-value** kehte hain.

| p-value | Matlab | Evidence score (−log₁₀ p) |
|---|---|---|
| 0.5 | aadhe normal windows isse zyada ajeeb → kuch khaas nahi | 0.3 |
| 0.01 | 100 normal windows mein 1 baar | **2** |
| 0.001 | 1000 mein 1 baar | 3 |
| 0.000001 | 10 lakh mein 1 baar | 6 |

Ye seekhne ke period ke "held-out" windows se banta hai (inhe **conformal p-value** kehte hain). Bahut zyada extreme scores ke liye ek statistics formula (**Extreme Value Theory**) use hota hai.

### 10.2 Fusion: 8 raayein ek mein (Cauchy combination)

8 p-values ko ek mein jodna hai. Mushkil ye hai ki jasoos **ek dusre se jude hain**: ek scan pe 3 jasoos ek saath bolte hain, aur seedha jodne se double-counting ho jaati hai. Humne **Cauchy combination test** (2020 ka statistics method) use kiya. Iske 2 achhe gun hain:

- **Ek jasoos bahut zor se chillaye** → thoda maana jaata hai, lekin uska shor 8 se "divide" jaisa ho jaata hai. Akela shor machane wala faisla nahi kar sakta.
- **Kai jasoos thoda-thoda bolein** → sab milke strong ho jaata hai.

Result: har device ke har 15 min ka ek **evidence score `s`** (0 se 30 tak).

### 10.3 CUSUM: "lagataar shak jodo"

Ek baar ka ajeeb window kuch bhi ho sakta hai, jaise kisi ne galti se kuch click kar diya. Lekin agar **lagataar** ajeeb ho, to dikkat hai.

**Piggy bank ki tarah:** har window mein `s − 2` jodo (2 se kam ho to kuch mat jodo, aur total kabhi 0 se neeche nahi jaata). Jab total **4 se upar** jaye, tab **ALARM**.

```text
Normal din:    s = 0.4, 0.3, 0.6 ...      → total 0 hi rehta hai          → koi alarm nahi
Ek blip:       s = 3 (ek baar)            → total 1, phir ghat ke 0        → koi alarm nahi
Dheema hacker: s = 3, 3, 3, 3, 3          → total 1, 2, 3, 4, 5 (>4)       → 5th window pe ALARM 🔔
Bada hamla:    s = 7 (config backdoor)    → total 5 turant                 → turant ALARM 🔔
```

Isse **ek-baar ke blips ignore** hote hain aur **dheere-dheere chalne wale (low-and-slow) attacks** bhi pakde jaate hain. Ye hata do to test mein 7 mein se **2 attacks miss** ho jaate hain.

### 10.4 Kill-chain corroboration: "2 alag sabooth chahiye"

**Police wali misaal:** kisi ko sirf isliye chor nahi kehte kyunki woh raat ko jaag raha tha. Lekin raat ko jaagna **+** taala todna **+** bag mein dusre ka saamaan = chor.

Isi tarah, alarm ke saath dekhte hain ki pichhle 24 ghante mein **kitne alag attack stages (tactics)** dikhe:

```text
                              ALARM? (lagataar ajeeb)
                                   │
                  nahi ────────────┼──────────── haan
                   │                              │
               ✓ CLEAN                  24 ghante mein kitne alag tactics?
                                    ┌─────────────┴─────────────┐
                                  0 ya 1                      2 ya zyada
                                    │                            │
                           ! SUSPICIOUS                   ✕ COMPROMISED
                           (analyst dekhe)                (turant action)
```

- **SUSPICIOUS:** kuch ajeeb chal raha hai, lekin abhi attack ka pakka saboot nahi. 24 ghante kuch na ho to wapas CLEAN.
- **COMPROMISED:** lagataar ajeeb **aur** 2+ attack stages (jaise C2 + Execution). Ye tab tak rehta hai jab tak insaan (analyst) khud na hataye.

**Lateral movement ka rule:** agar koi SUSPICIOUS device ko kisi **COMPROMISED device se naya successful connection** mila (scan nahi), to woh bhi COMPROMISED, kyunki "infection" faila hai. Example: file server ko hacked WS-03 se WinRM connection mila → file server COMPROMISED.

### 10.5 Gated learning: hacker ko "normal" mat seekhne do

Tool test ke time bhi seekhta rehta hai, lekin **sirf saaf windows se**. Agar seekhta hi rehta, to chalaak hacker dheere-dheere apna kaam badhata aur model use "normal" maan leta (ise **poisoning** kehte hain). Isliye shak wale windows kabhi baseline mein nahi jaate.

**Kimat:** koi asli naya kaam (jaise WS-07 ne naya DB app use karna shuru kiya) bhi SUSPICIOUS mein dikhta rahega, jab tak analyst **"Mark benign"** na dabaye. Ye jaan-boojh ke rakha gaya trade-off hai.

### 10.6 Incidents: jude hue devices ek case mein

Jo COMPROMISED devices aapas mein jude hain (ek ne dusre pe login kiya, connection banaya, ya dono ek hi hacker IP se baat kar rahe hain), unhe ek **incident** (ek case file) mein daal dete hain. Test mein **4 attack campaigns = 4 incidents** bane, bilkul sahi.

### 10.7 False alarms ki 8 deewarein (summary)

```text
 sab ajeeb windows
   │ 1. apna baseline + time of day          (backup roz 2 baje hota hai = normal)
   │ 2. calibrated p-values                   (threshold ka matlab pakka)
   │ 3. Cauchy fusion                         (akela shor machane wala faisla nahi karega)
   │ 4. CUSUM                                 (ek-baar ka blip ignore)
   │ 5. fleet consensus                       (update sab pe ek saath = normal)
   │ 6. maintenance window + known admin      (planned config change = normal)
   │ 7. 2+ attack stages                      (ek ajeeb cheez = sirf SUSPICIOUS)
   │ 8. gated learning + "Mark benign"        (poisoning nahi; analyst feedback)
   ▼
 bharose layak verdict
```

---

## Part 11 · Step ⑤ Output: website

Server chalao (Part 15) aur browser mein `http://127.0.0.1:5050` kholo. Website **black & white** design mein hai, aur status sirf rang se nahi, **shape + symbol + word** se dikhta hai:

| Status | Kaisa dikhta hai |
|---|---|
| ✕ COMPROMISED | **solid safed dabba**, kaale akshar |
| ! SUSPICIOUS | **dhaariyon (hatching) wala** dabba |
| ✓ CLEAN | halka outline |

### 11.1 Landing page (`/`)
Presentation jaisa page: problem, idea, engine, false-alarm layers, results. Upar right mein ek **live animation** hai jo asli attacks ko network pe chalte dikhati hai, saath mein terminal jaisa log.

### 11.2 Console (`/console`): asli tool

| Screen | Kya dikhata hai |
|---|---|
| **Timeline (upar)** | ▶ dabao to 3 din ka attack "replay" hota hai. Har tick = ek verdict change; tick pe click karo to wahan pahunch jaoge |
| **Overview** | network ka status, ginti (kitne hacked/suspicious/clean), network map (dashed chalti line = attack ka raasta), incidents, verdict feed |
| **Evidence matrix** | 22 devices × har 15 min, chamak = kitna ajeeb. Attacks **chamakti lakeeron** jaise dikhte hain |
| **Devices** | table: har device, verdict, trend line, attack stages |
| **Incidents** | har case ki ATT&CK strip (kaunse stages dikhe) + time ke hisaab se kahani |
| **Evaluation** | results, har scenario ka nateeja, ablation table |
| **Device report** (kisi device pe click) | kyun hacked bola, graph, kaunse jasoos bole, **kya badla vs normal**, config diff, beacon details, aur **kya karna chahiye** (forensic steps). Print bhi ho sakti hai |

**Buttons:**
- **Mark benign:** analyst bolta hai "ye theek hai", to device CLEAN ho jaata hai.
- **Export CEF:** company ke **SIEM** (Splunk, QRadar, Wazuh jaise central security software) mein bhejne ka format.
- **Export JSON:** poori report file.
- **Re-run analysis:** naya test hafta generate karta hai (~3 min, demo ke time mat dabana).

### 11.3 Docs (`/docs`)
17+ pages ki puri documentation, diagrams ke saath. **Page 15 (Presentation guide)** mein demo script aur judges ke sawaal-jawab hain. Ye page bhi wahin hai (Hinglish guide).

---

## Part 12 · Testing: humne kaise check kiya?

### 12.1 Simulation kyun?

Internet pe jo public datasets hain (CIC-IDS2017 wagairah), unmein **sirf network traffic** hai. Router ki config, firewall ke logs, laptops ke logins, sab **ek saath** kisi dataset mein nahi hain. Isliye humne ek **nakli lekin realistic company** banayi (`simulate.py`):

```text
 22 devices: 12 laptops (WS-01..12) · 4 servers (FILE, WEB, DB, DC)
             3 routers (CORE, EDGE, BRANCH) · 2 firewalls (PERIM, DC) · 1 network sensor (NET-CORE)
 7 din:      Thu–Sun = SEEKHNA (4 din)  →  Mon–Wed = TEST (3 din)
 414,080 events
```

Realistic banane ke liye: office hours, lunch break, weekend, log apni favourite websites kholte hain, kabhi-kabhi naye sites bhi, regular NTP/telemetry, roz raat backup, admin ka roz ka check, etc.

**Har hacker IP/domain bilkul random aur naya hai.** Koi IoC kaam hi nahi kar sakta.

### 12.2 Chaar attacks (kahani)

| | Attack | Kya hua | Kab pakda |
|---|---|---|---|
| **A1** | Laptop hack → file server | Mon 10:20: WS-03 pe email attachment se script chali → har 75s hacker ko call → 15:00 network scan (60 computers) → password guessing → 16:15 file server pe remote login (chori ke `svc_backup` password se) → raat 1-3 baje data bahar | WS-03: **usi 15-min window** mein (10:15)  ·  file server: Mon 17:00 |
| **A2** | Router hack | Mon 23:40: internet se 6 galat login, phir login → naya admin `maint` → hacker tak GRE tunnel → poore traffic ki copy (mirror) → **logging hata di** | **usi window** mein (23:30) |
| **A3** | Firewall backdoor | Tue 13:35: 40 galat login → rule "koi bhi DB server pe remote desktop kare" → naya superuser → management bahar khola → firewall khud hacker ko call kare → hacker DB server mein ghus ke data le gaya | firewall: usi window · DB server: 25 min baad |
| **A4** | DNS tunnel (dheema) | Wed 9-3 baje: WS-09 chupke se data ko lambe random DNS naamon mein chhupa ke bhejta raha | 45 min mein |

### 12.3 Chhe "jaal" (traps): normal kaam jo hacking jaisa dikhe

| | Trap | Nateeja |
|---|---|---|
| B1 | Saare 16 computers pe Windows update | ✓ CLEAN (fleet consensus ne bachaya) |
| B2 | WS-07 ne naya DB app use karna shuru kiya | ! SUSPICIOUS (sirf 1 stage, convict nahi) |
| B3 | Admin ne planned time pe router change kiya | ✓ CLEAN (maintenance window + known admin) |
| B4 | WS-11 raat 10 se 1 tak kaam karta raha | ✓ CLEAN |
| B5 | WS-05 ne 2 ghante dher saari nayi sites kholi | ✓ CLEAN |
| B6 | FW-DC se bada backup gaya | ! SUSPICIOUS (koi attack stage nahi) |

### 12.4 Final result

| Cheez | Result |
|---|---|
| Hacked devices pakde | **7 / 7** ✅ |
| Clean devices ko galti se "hacked" bola | **0 / 15** ✅ |
| Precision / Recall | **100% / 100%** |
| Average (median) pakadne ka time | **30 minute** |
| Suspicious mein gaye clean devices | 2 (WS-07, FW-DC), dono ka sahi kaaran hai |

### 12.5 Ablation: har hissa zaroori kyun hai?

"Ablation" = ek-ek hissa **hata ke** dekhna ki kya fark padta hai.

| Kya hataya | Asar |
|---|---|
| Fleet consensus | 13 clean devices pe alarm (2 ki jagah), 1 galat "hacked" |
| 2-sabooth rule | 2 clean devices galti se "hacked" |
| CUSUM | 2 attacks **miss** |
| Sirf Isolation Forest | 7 mein se sirf 1 pakda |
| Sirf Autoencoder | 7 pakde lekin ~5 ghante late + 1 galat |
| Sirf Config detector | 1 pakda (sirf router/firewall dekhta hai) |

**Seekh:** koi akela detector ya akela rule kaafi nahi. **Sab milke** best hai.

### 12.6 Imaandaari se kamiyan (judges ko khud batana)

1. **Data simulated hai.** Scenarios humne banaye. Asli data (CIC-IDS2017, CTU-13, LANL) aur asli router/firewall lab (GNS3/EVE-NG) pe test karna next step hai.
2. **Slips module live nahi chala.** Windows pe Docker/Redis nahi tha. Code Slips ke module structure ke hisaab se likha hai.
3. **Ek hi seed** (ek simulated hafta) ke numbers hain. "Re-run analysis" se naye hafte pe check kar sakte ho.
4. **Baseline saaf hona chahiye.** Agar seekhte waqt hi device hacked tha, to wo uska "normal" ban jaayega. Iska bachaav: peer comparison aur onboarding pe integrity check.

---

## Part 13 · Folder aur files: kaunsi file kya karti hai

```text
digital forsenics/
├── RESEARCH.md                          ← duniya bhar ki research ka survey
└── slips/                               ← Slips repo (humara base) + humara kaam
    ├── modules/compromise_detector/
    │   ├── compromise_detector.py       ← Slips ka NAYA module (Slips → UBT data)
    │   └── core/                        ← ENGINE (dimaag)
    │       ├── schema.py                ← UBT: event ka format, device list
    │       ├── features.py              ← 28 numbers ka report card, novelty, fleet consensus
    │       ├── detectors.py             ← 8 jasoos + calibration + Cauchy fusion
    │       ├── engine.py                ← poora faisla: CUSUM, 2-sabooth, verdict, incidents
    │       ├── pipeline.py              ← sab ek saath chalao + results + ablation + forensic steps
    │       ├── adapters.py              ← asli logs (syslog, Zeek, config files) → UBT
    │       └── simulate.py              ← nakli company + 4 attacks + 6 traps
    ├── modules/supported_module_names.py ← isme sirf 1 line joda (module register)
    ├── compromise_dashboard/            ← WEBSITE
    │   ├── server.py                    ← Flask server + API
    │   ├── __main__.py                  ← "python -m compromise_dashboard" yahin se chalta hai
    │   ├── data/results.json            ← analysis ka saved result
    │   └── static/                      ← landing / console / docs ke HTML, CSS, JS
    ├── trinetra_docs/                   ← documentation (ye file bhi yahin hai)
    ├── README.md                        ← project ka README (Slips wala ab SLIPS_README.md hai)
    └── run_trinetra.bat                 ← Windows pe double-click se chalao
```

**Ek line mein data ka safar:**
`simulate.py` (ya asli logs via `adapters.py`) → `schema.py` (UBT) → `features.py` (report card) → `detectors.py` (8 jasoos) → `engine.py` (faisla) → `pipeline.py` (results) → `server.py` → browser.

---

## Part 14 · Code ke andar ek window ka safar (thoda technical)

Jab engine ek 15-minute window process karta hai (`engine.py → detect_window`):

```text
1. Us window ke saare events uthao (har device ke)
2. Har device: kya NAYA dikha? → fleet consensus se company-wide changes hata do
3. 28 features banao → device ke apne normal pe scale karo
4. 8 detectors ke raw scores nikalo
5. Har score → p-value (calibration)
6. 8 p-values → Cauchy fusion → evidence s
7. CUSUM: S = max(0, S + s − 2);  S > 4 → ALARM
8. Agar s ≥ 3 ya alarm: "kyun?" likho (kaunsa feature, kaunsa jasoos, kaunse ATT&CK tactics)
9. Verdict update: CLEAN / SUSPICIOUS / COMPROMISED (2+ tactics rule, lateral movement rule)
10. Agar window saaf thi → baseline mein seekh lo (gated learning)
```

**Important numbers:**

| Cheez | Value |
|---|---|
| Window | 15 minute |
| CUSUM k / h | 2 / 4 |
| Tactics ki yaad / SUSPICIOUS se CLEAN hone ka time | 24 ghante |
| Fleet consensus | 20% devices (min 3), 1 ghante + 30 min look-ahead |
| Beacon | 3 ghante mein ≥ 8 contacts, regular gaps |
| Seekhna | 4 din (pehla din "warm-up", phir har teesra 2-ghante ka block calibration ke liye) |

---

## Part 15 · Chalana kaise hai

**Pehli baar:**

```bash
cd "C:\Users\thron\OneDrive\Desktop\digital forsenics\slips"
pip install -r compromise_dashboard/requirements.txt
python -m compromise_dashboard
```

Ya `slips` folder mein **`run_trinetra.bat` pe double-click** karo.

Browser mein kholo:

| Link | Kya |
|---|---|
| http://127.0.0.1:5050 | landing page |
| http://127.0.0.1:5050/console | console |
| http://127.0.0.1:5050/docs | docs |
| http://127.0.0.1:5050/console#device=RTR-EDGE | seedha router ki report |

Band karna ho to terminal mein **Ctrl + C**.

**Dikkat aaye to:**

| Problem | Kya karo |
|---|---|
| `No module named modules` | pakka karo ki command **`slips` folder ke andar** se chala rahe ho |
| Port busy | `python -m compromise_dashboard --port 5051` |
| "Analysing…" pe atka | terminal mein error dekho; `pip install -U scikit-learn scipy` |
| Naya test hafta chahiye | console mein "Re-run analysis" ya `python -m compromise_dashboard --rebuild --seed 11` |

---

## Part 16 · Demo kaise dena hai (5 minute)

| Time | Kya dikhana | Kya bolna |
|---|---|---|
| 0:00 | Landing page | "Routers aur firewalls duniya bhar mein hack ho rahe hain, aur IoC hafton baad aate hain. TRINETRA bina IoC ke, behaviour se pakadta hai." |
| 0:45 | Console overview | "22 devices ki company, 3 din baad: 7 hacked, 2 shak mein, 13 saaf." |
| 1:15 | ▶ Replay | "Monday 10:15: laptop pe naya program-chain + regular call, 2 stages, usi window mein pakda. File server lateral movement se juda. Raat 11:30 router hack." |
| 2:30 | RTR-EDGE pe click | "Internet se raat ko login, naya admin, tunnel, traffic copy, logging hataya. Hum config ka **matlab** samajhte hain, aur kisne/kab/kahan se badla. Neeche router ke liye action steps." |
| 3:30 | Evidence matrix → Incidents | "Chamakti lakeerein = 4 attacks. Halki jhilmil = humare traps. 4 incidents, har ek ki ATT&CK kahani." |
| 4:15 | Evaluation | "7/7 pakde, 0/15 galat. Windows update aur planned change pe koi galat alarm nahi. Ablation dikhata hai ki har layer kyun zaroori hai." |
| 4:45 | Docs | "Poori documentation, har detector ka maths, Slips integration." |

---

## Part 17 · Judges ke sawaal: simple jawab

**"Ye to bas anomaly detection hai, false alarms bahut aayenge?"**
Nahi. Hum anomaly ko seedha alarm nahi maante: pehle probability banate hain, 8 jasooson ko statistically jodte hain, lagataar hona zaroori hai (CUSUM), aur "hacked" bolne ke liye 2 alag attack stages chahiye. Isliye 15 clean devices mein se 0 galat.

**"Data nakli hai, bharosa kyun karein?"**
Kyunki koi public dataset router config + logs + laptop data + traffic ek saath nahi deta. Humne jaan-boojh ke traps daale jo humein bewakoof banane ke liye the. Next step: CIC-IDS2017, CTU-13, LANL aur GNS3 lab. Engine already Zeek, syslog, config files aur Slips output padhta hai.

**"Agar seekhte waqt hi device hacked ho?"**
Device apne aap ko normal lagega, lekin **peers** se alag dikhega: models device-type ke saare devices se seekhte hain, aur beacon/graph/config detectors poore network se compare karte hain. Onboarding pe firmware hash aur config check bhi.

**"Hacker bach sakta hai?"**
Use ek saath 8 jagah chhupna padega: traffic, DNS, logins, programs, log grammar, regularity, internal raaste aur config. Logging band karna bhi khud ek saboot hai. Dheema chalega to CUSUM jod lega. Baseline ko dheere-dheere sikhane se gated learning rokti hai.

**"Slips se kya alag hai?"**
Slips IP addresses ka network traffic dekhta hai. Humne devices ke hisaab se socha, routers/firewalls ka config aur logs joda, 8 jasooson ka calibrated fusion banaya, aur forensic report ke saath verdict diya. Slips ki raay humare 8 mein se ek vote hai.

**"Kitna bhaari hai?"**
Laptop CPU pe 22 devices ka ek hafta ~30 second mein. GPU nahi, internet nahi.

**"Deep learning kyun nahi har jagah?"**
Routers ke paas data kam hota hai, aur analyst ko **explanation** chahiye. Jahan zaroori hai wahan neural network (Autoencoder) aur sequence model hai, aur jahan guarantee chahiye wahan statistics.

---

## Part 18 · Shabdkosh (Glossary)

| Shabd | Simple matlab |
|---|---|
| **Compromised** | hacked; hacker ke control mein |
| **IoC** | hacker ke known nishaan (hash, IP, domain) |
| **LOTL (Living off the Land)** | hacker ne ghar ke hi auzaar (Windows ke tools, asli passwords) use kiye, koi malware file nahi |
| **Anomaly** | normal se alag cheez |
| **Baseline** | device ka seekha hua "normal" |
| **Feature** | behaviour ko batane wala ek number |
| **Window** | 15 minute ka hissa |
| **Novelty** | pehli baar dekhi gayi cheez |
| **Fleet consensus** | sab devices pe ek saath aaya badlaav = normal |
| **Detector** | ek "jasoos", yaani ek tareeka ajeebpan napne ka |
| **p-value** | "normal hota to itna ajeeb kitni baar dikhta" (0.01 = 100 mein 1) |
| **Calibration** | sab scores ko ek scale (probability) pe laana |
| **Fusion (Cauchy)** | 8 raayon ko statistically ek mein jodna |
| **CUSUM** | lagataar shak jodne wala counter |
| **Kill chain / ATT&CK tactic** | attack ke stages (C2, Persistence, Lateral Movement…) |
| **C2 (Command & Control)** | hacked device ka hacker ke server se contact |
| **Beacon** | regular "main zinda hoon" call |
| **Lateral Movement** | ek computer se dusre computer pe jaana |
| **Exfiltration** | data chura ke bahar bhejna |
| **Persistence** | tike rehne ka intezaam (nayi ID, naya rule) |
| **Defense Evasion** | chhupna (logs band karna) |
| **Config drift** | router/firewall ki rule-book mein badlaav |
| **Maintenance window** | planned changes ka time (humare test mein raat 1-3) |
| **Gated learning** | sirf saaf data se seekhna (anti-poisoning) |
| **SUSPICIOUS / COMPROMISED** | shak / pakka hacked |
| **Incident** | jude hue hacked devices ka ek case |
| **Precision / Recall** | galat alarm kitne kam / attacks kitne pakde |
| **False positive / negative** | galat alarm / miss hua attack |
| **Ablation** | ek hissa hata ke uski importance napna |
| **SIEM** | company ka central security software (Splunk, Wazuh) |
| **CEF** | SIEM mein alert bhejne ka format |
| **Slips** | humara base: open-source behavioural network IPS (CTU Prague) |
| **Zeek** | network ka "CCTV" jo packets ko logs mein badalta hai |
| **UBT** | humara common data format (8 event types) |

---

## Part 19 · Yaad karne layak 30-second pitch

> "Aaj routers, firewalls aur VPN devices hack ho rahe hain, aur IoC hafton baad aate hain. **TRINETRA** hacker ka chehra nahi, uska **behaviour** dekhta hai. Har device apna normal seekhta hai. **8 alag detectors** traffic, logins, programs, router logs, regular C2 calls, naye internal raaste aur config changes dekhte hain. Unki raay ko statistics se calibrate karke joda jaata hai. Device ko **hacked tabhi** kehte hain jab ajeebpan **lagataar** ho aur **2 alag attack stages** dikhein. Ek hi engine **system, firewall, router aur network** chaaron pe chalta hai. Hamare test mein **7/7 attacks pakde, 0 galat alarm**, aur Windows update ya planned change jaise traps pe tool bewakoof nahi bana. Ye **Slips** ke upar bana hai, bina internet laptop pe chalta hai, aur har device ki forensic report deta hai."
