/**
 * scan-engine.js  —  ThreatScan Engine v8.0
 * Deep static analysis with JVM Constant Pool parsing
 */
const ScanEngine = (() => {
  'use strict';

  const H = 'HIGH', M = 'MED', L = 'LOW';
  const _CFR = typeof ClassFileReader !== 'undefined'
    ? ClassFileReader
    : (typeof require !== 'undefined' ? require('./ClassFileReader') : null);

  /* ═══════════════════════════════════════════════════════
     MALWARE TYPE TAGS — used for UI category display
  ═══════════════════════════════════════════════════════ */

  const SIGS = [
    // ══════════════════════════════════════════════════════
    // 🔴 CATEGORY: STEALER — Account / Token / Credential Theft
    // ══════════════════════════════════════════════════════

    { id:'method_1674', sev:H, cat:'stealer', score:48, family:'Weedhack',
      title:'method_1674 — Fabric getSession() · Minecraft access token theft',
      type:'string', matcher:'method_1674',
      note:'Fabric intermediary name for MinecraftClient.getSession(). Confirmed in ExampleMod.class of this sample. Returns accessToken + UUID. #1 stealer method in all Fabric malware.' },

    { id:'method_1675', sev:H, cat:'stealer', score:38, family:'Weedhack',
      title:'method_1675 — Fabric session accessor pair',
      type:'string', matcher:'method_1675',
      note:'Paired accessor to method_1674 in the Fabric session token chain.' },

    { id:'method_1676', sev:H, cat:'stealer', score:36, family:'Weedhack',
      title:'method_1676 — Fabric getUsername() accessor',
      type:'string', matcher:'method_1676',
      note:'Found in ExampleMod.class. Used to get Minecraft username for exfil alongside token.' },

    { id:'method_44717', sev:H, cat:'stealer', score:34, family:'Weedhack',
      title:'method_44717 — Fabric player UUID accessor',
      type:'string', matcher:'method_44717',
      note:'Found in ExampleMod.class. Retrieves player UUID — part of the credential exfil package.' },

    { id:'method_1548', sev:M, cat:'stealer', score:18, family:'Weedhack',
      title:'method_1548 — Fabric getSession object accessor',
      type:'string', matcher:'method_1548',
      note:'Fabric intermediary for the session object getter. Called before method_1674/1676.' },

    { id:'get_session_direct', sev:H, cat:'stealer', score:32, family:'Generic',
      title:'getSession() / getAccessToken() — direct session call',
      type:'any', matcher:['getSession','getAccessToken','getSessionToken'],
      note:'Direct session token retrieval in class constants.' },

    { id:'access_token_field', sev:H, cat:'stealer', score:26, family:'Generic',
      title:'accessToken / authSession field reference',
      type:'any', matcher:['accessToken','authSession','sessionToken'],
      note:'Session token field being accessed or transmitted.' },

    // Launcher token files (fractureiser / Baikal targets)
    { id:'launcher_accounts', sev:H, cat:'stealer', score:36, family:'fractureiser',
      title:'launcher_accounts.json — vanilla Minecraft token file',
      context:['class','text','binary'],
      logic:{ all:['launcher_accounts','launcher_profiles','json'], min:2 },
      note:'Vanilla Minecraft launcher stores access tokens here. fractureiser and Baikal both target this path.' },

    { id:'feather_token', sev:H, cat:'stealer', score:42, family:'Stargazers/Baikal',
      title:'Feather client accounts.json — launcher token theft',
      type:'any', matcher:['feather','accounts','featherclient'],
      note:'Baikal Start.start() steals accounts.json from Feather client.' },

    { id:'essential_token', sev:H, cat:'stealer', score:40, family:'Stargazers/Baikal',
      title:'Essential mod microsoft_accounts.json — token theft',
      type:'any', matcher:['essential','microsoft_accounts','essentialmod'],
      note:'Baikal steals microsoft_accounts.json from Essential mod.' },

    { id:'lunar_token', sev:H, cat:'stealer', score:40, family:'Stargazers/Baikal',
      title:'Lunar client accounts.json — token theft',
      type:'any', matcher:['lunarclient','lunar','accounts'],
      note:'Baikal steals accounts.json from Lunar Client.' },

    { id:'discord_ldb', sev:H, cat:'stealer', score:36, family:'Stargazers/Baikal',
      title:'Discord leveldb token theft (.ldb files)',
      type:'any', matcher:['discord','leveldb','Local Storage','ldb'],
      note:'Baikal Class Discord: reads .ldb files from %APPDATA%/discord/Local Storage/leveldb.' },

    { id:'telegram_tdata', sev:H, cat:'stealer', score:34, family:'Stargazers/Baikal',
      title:'Telegram tdata exfiltration',
      type:'any', matcher:['tdata','stealTelegram','Telegram','zip'],
      note:'Baikal zips Telegram tdata folder and exfiltrates to C2.' },

    // MSA / Microsoft account (fractureiser)
    { id:'msastealer', sev:H, cat:'stealer', score:50, family:'fractureiser',
      title:'MSAStealer — Microsoft account refresh token theft',
      type:'string', matcher:'MSAStealer',
      note:'fractureiser MSAStealer steals MSA refresh tokens from LabyMod, Feather, Prism, MultiMC.' },

    { id:'refresh_token', sev:H, cat:'stealer', score:42, family:'fractureiser',
      title:'RefreshToken / extractRefreshTokens — MSA theft',
      type:'any', matcher:['RefreshToken','refreshToken','extractRefreshTokens','retrieveRefreshTokens'],
      note:'fractureiser MSA token theft chain.' },

    { id:'labymod_path', sev:H, cat:'stealer', score:38, family:'fractureiser',
      title:'LabyMod accounts.json — MSA token theft path',
      type:'any', matcher:['LabyMod','accounts','json','minecraft'],
      note:'fractureiser reads LabyMod accounts.json for MSA refresh tokens.' },

    // Browser / crypto / VPN (44 CALIBER stage 3)
    { id:'browser_creds', sev:H, cat:'stealer', score:28, family:'44 CALIBER',
      title:'Browser credential paths (Chrome/Edge/Firefox)',
      context:['class','text','binary'],
      logic:{ all:['Chrome','User','Data','Login','Data'], min:3 },
      note:'44 CALIBER steals credentials from Chrome, Edge, Firefox.' },

    { id:'crypto_wallets', sev:H, cat:'stealer', score:30, family:'44 CALIBER',
      title:'Crypto wallet targeting (Armory/Electrum/Exodus/Monero…)',
      type:'any', matcher:['Armory','AtomicWallet','BitcoinCore','Electrum','Exodus','Monero','MetaMask','wallet','dat'],
      note:'44 CALIBER explicitly targets all major crypto wallets.' },

    { id:'vpn_creds', sev:H, cat:'stealer', score:24, family:'44 CALIBER',
      title:'VPN credential theft (NordVPN/ProtonVPN/OpenVPN)',
      type:'any', matcher:['NordVPN','ProtonVPN','OpenVPN'],
      note:'44 CALIBER steals VPN credentials.' },

    // Discord webhook exfil
    { id:'webhook_full', sev:H, cat:'stealer', score:40, family:'Generic',
      title:'Discord webhook URL — credential exfil channel',
      context:['class','text','binary'],
      logic:{ all:['discord','api','webhooks'], min:3 },
      note:'Primary exfiltration channel in all Minecraft stealers.' },

    { id:'webhook_partial', sev:M, cat:'stealer', score:16, family:'Generic',
      title:'Discord webhook string (split / obfuscated)',
      type:'any', matcher:['discord','api','webhooks'],
      note:'Webhook URL assembled at runtime to evade static detection.' },

    // ══════════════════════════════════════════════════════
    // 🔴 CATEGORY: BOTNET — C2, Proxy, Remote Control
    // ══════════════════════════════════════════════════════

    { id:'mcfunny_su', sev:H, cat:'botnet', score:55, family:'Weedhack',
      title:'mcfunny.su — hardcoded C2/botnet hostname in ProxyManager',
      type:'regex', matcher:/mcfunny\.su/i,
      note:'CONFIRMED in ProxyManager.class. Uses Netty NioSocketChannel to connect. Botnet C2 endpoint.' },

    { id:'netty_bootstrap_c2', sev:H, cat:'botnet', score:38, family:'Weedhack',
      title:'Netty NioEventLoopGroup + Bootstrap — C2 connection setup',
      type:'any', matcher:['NioEventLoopGroup','Bootstrap','NioSocketChannel','netty','bootstrap'],
      note:'Netty bootstrap used in ProxyManager.checkPing() to connect to mcfunny.su C2.' },

    { id:'proxy_manager_c2', sev:H, cat:'rat', score:35, family:'Weedhack',
      title:'ProxyManager with external C2 connectivity',
      type:'any', matcher:['ProxyManager','checkPing','ThunderHackNextGen','misc','proxies','txt'],
      note:'ProxyManager loads proxies from file and connects to mcfunny.su to verify. Remote control capability.' },

    { id:'socks5_handler', sev:H, cat:'botnet', score:32, family:'Generic',
      title:'SOCKS5 protocol handler (Socks5CommandRequestDecoder)',
      type:'any', matcher:['Socks5CommandRequestDecoder','Socks4CommandRequestDecoder',
        'SocksAuthRequestDecoder','SocksAuthResponseDecoder'],
      note:'Full SOCKS5/SOCKS4 proxy protocol implementation embedded. Used for traffic routing through victim.' },

    { id:'netty_socks_codec', sev:M, cat:'botnet', score:20, family:'Generic',
      title:'io.netty SOCKS codec (proxy infrastructure)',
      type:'any', matcher:['netty','socks','codec'],
      note:'Netty SOCKS codec — full SOCKS4/5 proxy implementation.' },

    // Weedhack Ethereum C2
    { id:'weedhack_contract', sev:H, cat:'botnet', score:55, family:'Weedhack',
      title:'Ethereum contract 0x1280a841… — smart-contract C2 resolver',
      type:'string', matcher:'0x1280a841Fbc1F883365d3C83122260E0b2995B74',
      note:'Weedhack stores signed C2 URL on-chain. Change-resistant C2 — domain updated without touching the JAR.' },

    { id:'eth_selector', sev:H, cat:'botnet', score:48, family:'Weedhack',
      title:'Ethereum function selector 0xce6d41de',
      type:'string', matcher:'0xce6d41de',
      note:'ABI selector for the Weedhack C2 domain getter on the Ethereum contract.' },

    { id:'eth_rpc_clients', sev:H, cat:'botnet', score:40, family:'Weedhack',
      title:'CLIENTS field + Ethereum RPC endpoint list (FabricAdapter)',
      type:'any', matcher:['CLIENTS','eth','llamarpc','ethereum','rpc','publicnode','flashbots','tenderly','drpc','1rpc'],
      note:'CLIENTS array in FabricAdapter holds 32 public Ethereum RPC endpoints. Confirmed in this sample.' },

    { id:'magic_string', sev:H, cat:'botnet', score:38, family:'Weedhack',
      title:'MAGIC_STRING field in FabricAdapter — C2 auth token',
      type:'string', matcher:'MAGIC_STRING',
      note:'MAGIC_STRING constant used as authentication/verification token for C2 communication.' },

    { id:'rsa_public_key', sev:H, cat:'botnet', score:40, family:'Weedhack',
      title:'RSA_PUBLIC_KEY field — C2 domain signature verification',
      type:'string', matcher:'RSA_PUBLIC_KEY',
      note:'RSA-2048 public key in FabricAdapter.class used to verify signed C2 domain from Ethereum contract.' },

    { id:'weedhack_c2_domain', sev:H, cat:'botnet', score:58, family:'Weedhack',
      title:'whnewreceive.ru — active Weedhack C2 domain',
      type:'any', matcher:['whnewreceive','ru'],
      note:'Active Weedhack C2. POSTs username+uuid+accessToken to /api/delivery/handler.' },

    { id:'delivery_handler', sev:H, cat:'botnet', score:48, family:'Weedhack',
      title:'/api/delivery/handler — credential POST endpoint',
      type:'any', matcher:['api','delivery','handler'],
      note:'Exact HTTP endpoint where Weedhack sends stolen credentials.' },

    { id:'baikal_c2_ip', sev:H, cat:'botnet', score:50, family:'Stargazers/Baikal',
      title:'147.45.79.104 — Stargazers/Baikal C2 server IP',
      type:'any', matcher:['147','45','79','104'],
      note:'Confirmed C2 IP from Check Point Research June 2025. Used by Baikal to deliver .NET stealer.' },

    { id:'baikal_package', sev:H, cat:'botnet', score:52, family:'Stargazers/Baikal',
      title:'me.baikal.club — Stargazers/Baikal C2 package',
      type:'any', matcher:['me','baikal','club'],
      note:'Both stage-1 and stage-2 of Baikal stealer use this package namespace.' },

    { id:'pastebin_loader', sev:H, cat:'botnet', score:44, family:'Stargazers/Baikal',
      title:'Pastebin raw URL — base64 C2 dead-drop',
      type:'any', matcher:['pastebin','raw'],
      note:'Baikal reads Base64-encoded stage-2 IP from Pastebin. User JoeBidenMama. 1500+ hits.' },

    { id:'fractureiser_nekoclient', sev:H, cat:'botnet', score:50, family:'fractureiser',
      title:'dev.neko/nekoclient — fractureiser stage-3 C2 package',
      type:'any', matcher:['dev','neko','nekoclient'],
      note:'fractureiser stage-3 C2 client. Includes MSA stealer and browser credential collection.' },

    // Raw socket / HTTP C2
    { id:'raw_external_ip', sev:H, cat:'botnet', score:32, family:'Generic',
      title:'Hardcoded external IP address (non-private)',
      type:'regex', matcher:/https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d{2,5})?(?:\/[\w\-./?%&=]*)?/i,
      note:'Hardcoded C2 or exfil IP in class constants.' },

    { id:'external_url', sev:M, cat:'botnet', score:14, family:'Generic',
      title:'External URL (non-Minecraft CDN)',
      type:'regex', matcher:/https?:\/\/(?![^\s/]*(?:minecraft|mojang|fabricmc|curseforge|modrinth|github|gitlab|maven|repo|apache|sonatype|s3\.amazonaws\.com))[^\s"']+/i,
      note:'HTTP request to suspicious external domain (excludes common safe CDNs).' },

    { id:'urlclassloader_url_combo', sev:H, cat:'loader', score:48, family:'Generic loader',
      title:'URLClassLoader + URL combo (runtime fetch + load)',
      context:['class','text','binary'],
      logic:{ all:['URLClassLoader','http','://'] },
      note:'Stage-1 dropper pattern: fetch remote URL then load via URLClassLoader.' },

    { id:'urlclassloader_loadclass_combo', sev:H, cat:'loader', score:52, family:'Generic loader',
      title:'URLClassLoader + loadClass + URL (multi-stage dropper)',
      context:['class','text','binary'],
      logic:{ all:['URLClassLoader','loadClass','http','://'], min:3 },
      note:'Multi-stage loader that downloads a class/JAR and calls loadClass immediately.' },

    // ══════════════════════════════════════════════════════
    // 🔴 CATEGORY: LOADER — Downloads / Executes Payloads
    // ══════════════════════════════════════════════════════

    { id:'stagewithcontext', sev:H, cat:'loader', score:42, family:'Weedhack',
      title:'stageWithContext() — in-memory stage-2 downloader',
      type:'string', matcher:'stageWithContext',
      note:'CONFIRMED in Helper.class and Entrypoint.class of this sample. Downloads stage-2 JAR via HTTP.' },

    { id:'jar_inputstream_defineclass', sev:H, cat:'loader', score:42, family:'Weedhack',
      title:'JarInputStream + defineClass — disk-bypass in-memory loader',
      type:'any', matcher:['JarInputStream','jar','defineClass'],
      note:'CONFIRMED in Helper.class. Loads downloaded JAR entirely in-memory — no file written to disk.' },

    { id:'defineclass_inject', sev:H, cat:'loader', score:32, family:'Generic',
      title:'defineClass — dynamic bytecode injection',
      type:'string', matcher:'defineClass',
      note:'Loads arbitrary compiled bytecode at runtime. Core of Weedhack ExampleMixin ClassLoader.' },

    { id:'inmemory_classloader', sev:H, cat:'loader', score:38, family:'Weedhack',
      title:'ExampleMixin — in-memory ClassLoader (disk-bypass)',
      type:'any', matcher:['ExampleMixin','classDefinitions','resourceDefinitions','classMap','resourceMap'],
      note:'Custom ClassLoader in ExampleMixin.class. Takes classMap+resourceMap to load JAR without touching disk.' },

    { id:'files_jar_module', sev:H, cat:'loader', score:45, family:'Weedhack',
      title:'/files/jar/module — Weedhack stage-2 JAR download path',
      type:'any', matcher:['files','jar','module'],
      note:'HTTP GET to this path downloads Module.jar stage-2 payload.' },

    { id:'mixinloader', sev:H, cat:'loader', score:44, family:'Stargazers/Baikal',
      title:'MixinLoader-v2.4.jar — Baikal stage-2 filename',
      type:'string', matcher:'MixinLoader',
      note:'Stage-2 stealer JAR name downloaded by Baikal SSHaccess class.' },

    { id:'sshaccess', sev:H, cat:'loader', score:48, family:'Stargazers/Baikal',
      title:'SSHaccess class — 44 CALIBER .NET stealer downloader',
      type:'string', matcher:'SSHaccess',
      note:'SSHaccess downloads and runs the 44 CALIBER .NET stealer payload.' },

    { id:'urlclassloader', sev:H, cat:'loader', score:25, family:'Generic',
      title:'URLClassLoader — remote JAR/class loading',
      type:'any', matcher:['URLClassLoader','ClassLoader','URL'],
      note:'Downloads and executes remote JAR or class files.' },

    { id:'libwebgl64', sev:H, cat:'loader', score:52, family:'fractureiser',
      title:'libWebGL64.jar — fractureiser stage-1 dropper',
      type:'any', matcher:['libWebGL64','jar'],
      note:'fractureiser drops this to %LOCALAPPDATA%\\Microsoft Edge\\ for Windows persistence.' },

    { id:'processbuilder_exec', sev:H, cat:'loader', score:28, family:'Generic',
      title:'ProcessBuilder — spawns system processes',
      type:'any', matcher:['ProcessBuilder','process'],
      note:'8 refs confirmed in this sample. Used by Entrypoint.class for javaw.exe relaunch.' },

    { id:'runtime_exec', sev:H, cat:'loader', score:25, family:'Generic',
      title:'Runtime.exec — OS command execution',
      type:'any', matcher:['Runtime','exec'],
      note:'Executes OS commands from Java.' },

    { id:'exe_execution', sev:H, cat:'loader', score:28, family:'Generic',
      title:'EXE file execution (.exe reference in class)',
      type:'any', matcher:['exe','ProcessBuilder','explorer','cmd','powershell'],
      note:'References to .exe file execution in class constants.' },

    // ══════════════════════════════════════════════════════
    // 🟡 CATEGORY: SPYWARE — Tracking / Surveillance
    // ══════════════════════════════════════════════════════

    { id:'telemetry_api', sev:H, cat:'spyware', score:38, family:'Weedhack',
      title:'api.thunderhack.net — telemetry server (player tracking)',
      type:'any', matcher:['api','thunderhack','v1','users'],
      note:'CONFIRMED in TelemetryManager.class. Sends username + online status to api.thunderhack.net. Tracks all users.' },

    { id:'telemetry_online_ping', sev:H, cat:'spyware', score:34, family:'Weedhack',
      title:'pingServer() sends username to remote tracker',
      type:'any', matcher:['pingServer','api','thunderhack','v1','users','online','name'],
      note:'TelemetryManager pingServer periodically sends player name to https://api.thunderhack.net/v1/users/online?name=<username>.' },

    { id:'telemetry_helper_class', sev:H, cat:'spyware', score:32, family:'Weedhack',
      title:'TelemetryHelper — Stage-2 data exfil class',
      type:'string', matcher:'TelemetryHelper',
      note:'Weedhack Stage-2 exfiltration class. initTelemetry() sends all collected data.' },

    { id:'checkip_amazonaws', sev:M, cat:'spyware', score:20, family:'Stargazers/Baikal',
      title:'checkip.amazonaws.com — victim IP harvesting',
      type:'any', matcher:['checkip','amazonaws','com'],
      note:'Baikal calls checkip.amazonaws.com to get the victim\'s external IP for exfil payload.' },

    { id:'screenshot_capture', sev:M, cat:'spyware', score:16, family:'44 CALIBER',
      title:'Screenshot capture (Robot.createScreenCapture)',
      type:'any', matcher:['createScreenCapture','Robot','getScreenCapture'],
      note:'44 CALIBER stage-3 captures screenshots of victim desktop.' },

    { id:'clipboard_capture', sev:M, cat:'spyware', score:14, family:'44 CALIBER',
      title:'Clipboard contents access',
      type:'any', matcher:['getSystemClipboard','getContents','Clipboard'],
      note:'Captures clipboard — intercepts crypto wallet addresses.' },

    { id:'discord_token_re', sev:H, cat:'spyware', score:30, family:'Generic',
      title:'Discord auth token pattern',
      type:'any', matcher:['discord','token','mfa'],
      note:'Hardcoded Discord user auth token pattern.' },

    // ══════════════════════════════════════════════════════
    // 🟡 CATEGORY: DROPPER — Persistence / Startup
    // ══════════════════════════════════════════════════════

    { id:'javaw_relaunch', sev:H, cat:'dropper', score:26, family:'Weedhack',
      title:'javaw.exe --jw relaunch — console window hiding',
      type:'any', matcher:['javaw','exe'],
      note:'CONFIRMED in Entrypoint.class. Weedhack relaunches via javaw.exe to hide console window on standalone run.' },

    { id:'fabric_api_json_uuid', sev:H, cat:'dropper', score:28, family:'Weedhack',
      title:'fabric.api.json + api_version — Weedhack campaign UUID',
      type:'any', matcher:['fabric','api','json','api_version'],
      note:'CONFIRMED in Helper.class. Fake fabric.api.json stores campaign UUID sent to C2 as userId.' },

    { id:'cmstp_bypass', sev:H, cat:'dropper', score:44, family:'Weedhack',
      title:'CMSTP.exe UAC bypass (MITRE T1218.003)',
      type:'any', matcher:['cmstp','exe','Elevator','xdmf'],
      note:'Weedhack Elevator class bypasses UAC via cmstp.exe + .xdmf config files.' },

    { id:'adddefenderexclusions', sev:H, cat:'dropper', score:44, family:'Weedhack',
      title:'addDefenderExclusions() — Windows Defender evasion',
      type:'string', matcher:'addDefenderExclusions',
      note:'Modifies Defender exclusion paths via Set-MpPreference after UAC bypass.' },

    { id:'registry_autorun', sev:H, cat:'dropper', score:28, family:'Generic',
      title:'Windows registry Run key — autostart persistence',
      type:'any', matcher:['CurrentVersion','Run','HKEY_CURRENT_USER','HKCU','Software','WinRegistry'],
      note:'Writes to Windows startup registry for persistence across reboots.' },

    { id:'appdata_drop', sev:H, cat:'dropper', score:24, family:'Generic',
      title:'File drop to AppData\\Roaming',
      type:'any', matcher:['AppData','Roaming','APPDATA'],
      note:'Drops file to user roaming directory for persistence.' },

    { id:'startup_folder', sev:H, cat:'dropper', score:26, family:'Generic',
      title:'Windows Startup folder shortcut',
      type:'any', matcher:['Startup','shell','startup','lnk'],
      note:'Shortcut in Startup folder — executes on every login.' },

    { id:'linux_persistence', sev:H, cat:'dropper', score:20, family:'fractureiser',
      title:'Linux systemd persistence (fractureiser)',
      type:'any', matcher:['systemd','utility','service','config','data','etc','rc','local'],
      note:'fractureiser Linux persistence via systemd service file.' },

    // ══════════════════════════════════════════════════════
    // 🟠 CATEGORY: OBFUSC — Obfuscation & Anti-Analysis
    // ══════════════════════════════════════════════════════

    { id:'weedhack_helper_load', sev:H, cat:'obfusc', score:42, family:'Weedhack',
      title:'Helper.load() — Weedhack S-box + XOR + bit-rotation cipher',
      context:['class','text','binary'],
      logic:{ all:['com/example/Helper','load'] },
      note:'CONFIRMED via Helper.class fields: value, shift, rotated, substituted, invSbox, state. k1=187 k2=67. Hides all sensitive strings.' },

    { id:'jnic_package', sev:H, cat:'obfusc', score:44, family:'JNIC',
      title:'dev.jnic.kWGlIS — JNIC native obfuscator',
      type:'any', matcher:['dev','jnic','kWGlIS'],
      note:'JNIC compiles Java to native DLL. All method bodies invisible from bytecode.' },

    { id:'jnic_loader', sev:H, cat:'obfusc', score:40, family:'JNIC',
      title:'JNICLoader — LZMA native DLL decompressor',
      type:'string', matcher:'JNICLoader',
      note:'Decompresses win-x64/arm64 DLL from .dat resource and loads via System.load().' },

    { id:'jnic_method_stub', sev:H, cat:'obfusc', score:36, family:'JNIC',
      title:'$jnicLoader() / $jnicClinit() — JNIC native stubs',
      type:'any', matcher:['jnicLoader','jnicClinit'],
      note:'All real logic is in a compiled native DLL — not readable from Java bytecode.' },

    { id:'skidfuscator', sev:M, cat:'obfusc', score:15, family:'Skidfuscator',
      title:'Skidfuscator obfuscator detected',
      type:'any', matcher:['skidfuscator','dev','skidfuscator'],
      note:'#1 obfuscator used by Minecraft malware devs. Baikal samples confirmed by Check Point Research.' },

    { id:'radon', sev:M, cat:'obfusc', score:12, family:'Radon',
      title:'Radon obfuscator detected',
      type:'any', matcher:['me','itzsomebody','radon','runtime'],
      note:'Java obfuscator with string encryption and flow obfuscation.' },

    { id:'bcel_encoded', sev:H, cat:'obfusc', score:20, family:'Generic',
      title:'$BCEL$ Apache BCEL encoded class',
      type:'string', matcher:'BCEL',
      note:'Loads obfuscated bytecode via Apache BCEL class loader.' },

    { id:'fractureiser_byte_array', sev:H, cat:'obfusc', score:32, family:'fractureiser',
      title:'new String(new byte[]{…}) — fractureiser string obfuscation',
      context:['class','text','binary'],
      logic:{ all:['new','String','byte'], min:2 },
      note:'fractureiser stage-0 uses byte array literals to hide strings from static scanners.' },

    { id:'xor_string_decoder', sev:H, cat:'obfusc', score:36, family:'Generic',
      title:'XOR string decode loop (bytecode heuristic)',
      context:['class'],
      logic:{ any:['String','byte','char','xor'], min:2 },
      requiresXor: true,
      requiresArrayOps: true,
      note:'Detects XOR decode loops using bytecode opcodes + string/byte constants.' },

    { id:'reflection_setaccessible', sev:M, cat:'obfusc', score:14, family:'Generic',
      title:'setAccessible — reflection access bypass',
      type:'string', matcher:'setAccessible',
      note:'Bypasses Java access modifiers to reach private Minecraft session methods.' },

    // ══════════════════════════════════════════════════════
    // FILE SIGNATURES
    // ══════════════════════════════════════════════════════

    { id:'discord_rpc_dll', sev:H, cat:'botnet', score:42, family:'BambooWare',
      title:'win32-x86-64/discord-rpc.dll — embedded native Windows DLL',
      type:'file', matcher:'discord-rpc',
      note:'Native discord-rpc.dll embedded in JAR. CONFIRMED in this sample. BambooWare IOC.' },

    { id:'discord_rpc_so', sev:M, cat:'botnet', score:20, family:'BambooWare',
      title:'linux-x86-64/libdiscord-rpc.so — embedded Linux library',
      type:'file', matcher:'libdiscord-rpc',
      note:'Linux native discord-rpc shared library embedded in JAR.' },

    { id:'jnic_dat_resource', sev:H, cat:'obfusc', score:34, family:'JNIC',
      title:'UUID .dat resource — embedded JNIC native DLL',
      type:'file', matcher:'dat',
      note:'JNIC stores LZMA-compressed native DLL in UUID-named .dat file.' },

    { id:'nested_jar', sev:H, cat:'loader', score:22, family:'Generic',
      type:'file', matcher:'jar',
      title:'Nested JAR inside archive (multi-stage dropper)',
      note:'JAR-in-JAR — standard multi-stage loader technique.' },

    { id:'libwebgl_file', sev:H, cat:'dropper', score:52, family:'fractureiser',
      type:'file', matcher:'libWebGL64',
      title:'libWebGL64.jar — fractureiser stage-1 dropper resource',
      note:'fractureiser drops this to %LOCALAPPDATA%\\Microsoft Edge\\.' },

    // ══════════════════════════════════════════════════════
    // KNOWN MALWARE FAMILY STRINGS
    // ══════════════════════════════════════════════════════

    { id:'bamboo_examplemod', sev:H, cat:'botnet', score:45, family:'BambooWare/Weedhack',
      title:'com.example.ExampleMod — known Weedhack/BambooWare entrypoint',
      type:'any', matcher:['com','example','ExampleMod'],
      note:'Exact malicious Fabric entrypoint CONFIRMED in this sample.' },

    { id:'bamboo_fabric_adapter', sev:H, cat:'botnet', score:42, family:'BambooWare/Weedhack',
      title:'com.example.FabricAdapter — Ethereum RPC C2 resolver',
      type:'any', matcher:['com','example','FabricAdapter'],
      note:'CONFIRMED in this sample. Implements Ethereum RPC calls to resolve C2 domain.' },

    { id:'bamboo_helper', sev:H, cat:'obfusc', score:44, family:'BambooWare/Weedhack',
      title:'com.example.Helper — Weedhack string cipher + stage loader',
      type:'any', matcher:['com','example','Helper'],
      note:'CONFIRMED in this sample. Contains S-box cipher + JarInputStream stage loader.' },

    { id:'bamboo_examplemixin', sev:H, cat:'loader', score:40, family:'BambooWare/Weedhack',
      title:'com.example.ExampleMixin — in-memory ClassLoader',
      type:'any', matcher:['com','example','ExampleMixin'],
      note:'CONFIRMED in this sample. Custom ClassLoader for in-memory bytecode execution.' },

    { id:'bamboo_entrypoint', sev:H, cat:'loader', score:38, family:'BambooWare/Weedhack',
      title:'com.example.Entrypoint — standalone malware entry class',
      type:'any', matcher:['com','example','Entrypoint'],
      note:'CONFIRMED in this sample. Standalone JAR entry — relaunches via javaw.exe.' },

    { id:'bamboo_resource', sev:H, cat:'dropper', score:48, family:'BambooWare',
      title:'BambooWare known malware resource signature',
      type:'file', matcher:'bamboo',
      note:'Known BambooWare resource file. MCAntiMalware: Family.BambooWare.' },

    { id:'dev_majanito', sev:H, cat:'botnet', score:50, family:'Weedhack',
      title:'dev.majanito — Weedhack stage-2 package',
      type:'any', matcher:['dev','majanito'],
      note:'Stage-2 classes: Main, Elevator, RPCHelper, TelemetryHelper, IMCL.' },

    { id:'initializeweedhack', sev:H, cat:'loader', score:52, family:'Weedhack',
      title:'initializeWeedhack() — Weedhack stage-2 entry method',
      type:'string', matcher:'initializeWeedhack',
      note:'Exact method reflectively invoked on dev.majanito.Main.' },

    { id:'mc_stealer_names', sev:H, cat:'stealer', score:44, family:'Generic',
      title:'Known Minecraft stealer family name in class strings',
      type:'any', matcher:['weedhack','fracture','stealer','vortex','grab','luna','blaze','nekoclient','baikal'],
      note:'Known Minecraft malware family name in class constants.' },

    { id:'caliber_title', sev:H, cat:'stealer', score:52, family:'44 CALIBER',
      title:'44 CALIBER — .NET stealer assembly title string',
      type:'string', matcher:'44 CALIBER',
      note:'Exact .NET assembly title of the 44 CALIBER stealer downloaded by Baikal SSHaccess.' },

    { id:'caliber_russian', sev:H, cat:'stealer', score:45, family:'44 CALIBER',
      title:'Russian exfil strings (пассвордс, спиздил, дискорд)',
      type:'any', matcher:['пассвордс','спиздил','нордвпн','протонвпн','дискорд'],
      note:'Russian comment strings in 44 CALIBER exfil message.' },

    { id:'rat_names', sev:H, cat:'rat', score:34, family:'Generic RAT',
      title:'Known Java RAT family name',
      type:'any', matcher:['jRAT','j-RAT','Adwind','STRRAT','Qealler','Ratty','DarkComet','NanoCore','AlienSpy'],
      note:'Direct match to known Java RAT family name.' },

    { id:'rat_screen', sev:H, cat:'rat', score:32, family:'Generic RAT',
      title:'Remote screen capture / desktop streaming',
      type:'any', matcher:['Robot','createScreenCapture','DesktopCapture'],
      note:'RAT capability: screen capture or live desktop streaming.' },

    { id:'rat_keylog', sev:H, cat:'rat', score:36, family:'Generic RAT',
      title:'Keylogger hooks (keyboard capture)',
      type:'any', matcher:['KeyListener','nativeKeyPressed','KeyboardHook','JNativeHook'],
      note:'RAT capability: keyboard logging / input capture.' },

    { id:'rat_webcam', sev:H, cat:'rat', score:30, family:'Generic RAT',
      title:'Webcam access / capture',
      type:'any', matcher:['javax','imageio','ImageIO','Webcam','OpenIMAJ','sarxos','webcam'],
      note:'RAT capability: webcam access.' },

    { id:'rat_shell', sev:H, cat:'rat', score:34, family:'Generic RAT',
      title:'Remote shell / command execution handler',
      type:'any', matcher:['cmd','powershell','bin','sh','bash','Runtime','exec','ProcessBuilder'],
      note:'RAT capability: remote shell and command execution.' },

    { id:'rat_password_grab', sev:H, cat:'stealer', score:38, family:'Generic RAT',
      title:'Password/credential grabbing strings',
      type:'any', matcher:['password','txt','Login Data','logins','json','key3','key4','cookies','sqlite'],
      note:'RAT capability: browser password harvesting.' },

    { id:'vm_detection', sev:M, cat:'obfusc', score:14, family:'Stargazers/Baikal',
      title:'VM/sandbox detection (VBoxTray, vmtoolsd, Wireshark…)',
      type:'any', matcher:['VBoxTray','vmtoolsd','Wireshark','virtualbox','vmware','VBoxService'],
      note:'Baikal checks for analysis tools via tasklist.exe. Terminates if found.' },

    { id:'aes_cipher', sev:M, cat:'obfusc', score:10, family:'Generic',
      title:'AES SecretKeySpec — payload/string encryption',
      type:'any', matcher:['SecretKeySpec','IvParameterSpec','AES','CBC','GCM'],
      note:'Symmetric encryption for hiding strings or payloads.' },

    // ══════════════════════════════════════════════════════
    // FLOW INDICATORS (AND / Proximity)
    // ══════════════════════════════════════════════════════

    { id:'inmemory_loader_combo', sev:H, cat:'loader', score:60, family:'Generic loader',
      title:'defineClass + URLClassLoader + Cipher — in-memory loader chain',
      context:['class'],
      logic:{ all:['defineClass','URLClassLoader','Cipher'] },
      note:'Composite indicator: dynamic loading + crypto usage detected in constant pool.' },

    { id:'defineclass_urlcl_prox', sev:H, cat:'loader', score:52, family:'Generic loader',
      title:'defineClass close to URLClassLoader (proximity)',
      context:['class'],
      logic:{ proximity:[{ a:'defineClass', b:'URLClassLoader', within:50 }] },
      note:'Loader patterns clustered in constant pool entries suggest staged class loading.' },
  ];

  const FAMILY_MAP = {
    'Weedhack':            { display:'Family.WEEDHACK' },
    'BambooWare':          { display:'Family.BAMBOOWARE' },
    'BambooWare/Weedhack': { display:'Family.WEEDHACK' },
    'Stargazers/Baikal':   { display:'Family.BAIKAL' },
    'fractureiser':        { display:'Family.FRACTUREISER' },
    '44 CALIBER':          { display:'Family.44CALIBER' },
    'JNIC':                { display:'Packer.JNIC' },
    'Skidfuscator':        { display:'Obfuscator.SKIDFUSCATOR' },
    'Generic RAT':         { display:'Family.RAT' },
    'Generic':             { display:'Malware.GENERIC' },
    'Generic loader':      { display:'Trojan.LOADER' },
  };

  const CAT_CONFIG = {
    stealer: { label:'STEALER',  color:'#e83040', icon:'🔑', desc:'Account & credential theft' },
    botnet:  { label:'BOTNET',   color:'#e87030', icon:'🌐', desc:'C2 communication & remote control' },
    rat:     { label:'RAT',      color:'#ff5d9e', icon:'🛰', desc:'Remote access & interactive control' },
    loader:  { label:'LOADER',   color:'#e8c020', icon:'⬇',  desc:'Payload download & execution' },
    spyware: { label:'SPYWARE',  color:'#c050e8', icon:'👁',  desc:'Surveillance & data collection' },
    dropper: { label:'DROPPER',  color:'#e05080', icon:'💾',  desc:'Persistence & file installation' },
    obfusc:  { label:'OBFUSC',   color:'#5080e8', icon:'🔒', desc:'Obfuscation & anti-analysis' },
  };

  const DANGEROUS = new Set([
    'method_1674','method_1675','method_1676','method_44717','method_1548',
    'getSession','getAccessToken','accessToken',
    'mcfunny.su','api.thunderhack.net','whnewreceive.ru',
    '0x1280a841Fbc1F883365d3C83122260E0b2995B74','0xce6d41de',
    '/api/delivery/handler','/files/jar/module',
    'stageWithContext','initializeWeedhack','dev.majanito',
    'com.example.ExampleMod','com.example.Helper','com.example.FabricAdapter',
    'com.example.ExampleMixin','com.example.Entrypoint',
    'MAGIC_STRING','RSA_PUBLIC_KEY','CLIENTS',
    'Helper.load','JNICLoader','$jnicLoader',
    'fabric.api.json','api_version',
    'me.baikal.club','Baikal','SSHaccess','MixinLoader','147.45.79.104',
    'MSAStealer','nekoclient','RefreshToken','libWebGL64.jar',
    'discord.com/api/webhooks','44 CALIBER','FuckTheSystem',
    'пассвордс','спиздил',
    'wallet.dat','MetaMask','Electrum',
    'cmd.exe','powershell','pastebin.com',
    'addDefenderExclusions','cmstp.exe','TelemetryHelper',
    'Skidfuscator','$$BCEL$$',
  ]);

  const BINARY_EXTENSIONS = /\.(dll|so|dylib|bin|dat|exe|bat|ps1|sh|enc)$/i;

  function readClassConstants(buf) {
    if (!_CFR) throw new Error('ClassFileReader is required');
    return _CFR.parse(buf);
  }

  function extractBinaryStrings(buf, minLen = 4) {
    const bytes = new Uint8Array(buf);
    const out = [];
    let cur = '';
    for (const b of bytes) {
      if (b >= 0x20 && b < 0x7F) cur += String.fromCharCode(b);
      else {
        if (cur.length >= minLen) out.push(cur);
        cur = '';
      }
    }
    if (cur.length >= minLen) out.push(cur);
    return out;
  }

  function normalizeSig(sig) {
    if (sig.logic) return sig;
    if (sig.type === 'file') {
      const matcher = sig.matcher;
      const isRegex = matcher instanceof RegExp;
      if (isRegex) return { ...sig, context: ['file'], logic: { regex: [matcher] } };
      const any = Array.isArray(matcher) ? matcher : [matcher];
      return { ...sig, context: ['file'], logic: { any } };
    }
    if (sig.type === 'regex') {
      return { ...sig, context: ['class', 'text', 'binary'], logic: { regex: [sig.matcher] } };
    }
    if (sig.type === 'any') {
      return { ...sig, context: ['class', 'text', 'binary'], logic: { any: sig.matcher } };
    }
    if (sig.type === 'string') {
      return { ...sig, context: ['class', 'text', 'binary'], logic: { any: [sig.matcher] } };
    }
    return { ...sig, context: ['class', 'text', 'binary'], logic: { any: [sig.matcher] } };
  }

  const ALLOWLIST_SHA256 = new Set([
    // Known-good mods (placeholder entries can be updated as needed)
  ]);

  function isAllowlistedSha256(sha) {
    return ALLOWLIST_SHA256.has(sha);
  }

  function addAllowlistSha256(sha) {
    if (sha) ALLOWLIST_SHA256.add(sha);
  }

  const NORMALIZED_SIGS = SIGS.map(normalizeSig);

  function findToken(strings, token) {
    if (token instanceof RegExp) {
      for (const s of strings) {
        const m = s.match(token);
        if (m) return m[0];
      }
      return null;
    }
    for (const s of strings) {
      if (s.includes(token)) return s;
    }
    return null;
  }

  function positionsForToken(strings, token) {
    const out = [];
    if (token instanceof RegExp) {
      for (let i = 0; i < strings.length; i++) {
        if (token.test(strings[i])) out.push(i);
      }
      return out;
    }
    for (let i = 0; i < strings.length; i++) {
      if (strings[i].includes(token)) out.push(i);
    }
    return out;
  }

  function extractDiscordWebhook(strings) {
    const re = /https?:\/\/discord(?:app)?\.com\/api\/webhooks\/\d{17,19}\/[\w\-]{20,}/;
    for (const s of strings) {
      const m = s.match(re);
      if (m) return m[0];
    }
    return null;
  }

  function evalLogic(strings, logic) {
    if (!logic) return null;
    const minMatch = Math.max(1, logic.min || 0);
    if (logic.all) {
      let first = null;
      let matched = 0;
      for (const token of logic.all) {
        const hit = findToken(strings, token);
        if (hit) {
          matched++;
          if (!first) first = hit;
        } else if (minMatch === 0 || matched >= minMatch) {
          continue;
        } else {
          return null;
        }
      }
      if (minMatch > 0 && matched < minMatch) return null;
      return first || logic.all[0];
    }
    if (logic.any) {
      let matched = 0;
      let first = null;
      for (const token of logic.any) {
        const hit = findToken(strings, token);
        if (hit) {
          matched++;
          if (!first) first = hit;
          if (matched >= Math.max(1, minMatch)) return first;
        }
      }
      return null;
    }
    if (logic.regex) {
      for (const re of logic.regex) {
        const hit = findToken(strings, re);
        if (hit) return hit;
      }
      return null;
    }
    if (logic.proximity) {
      for (const rule of logic.proximity) {
        const aPos = positionsForToken(strings, rule.a);
        const bPos = positionsForToken(strings, rule.b);
        for (const a of aPos) {
          for (const b of bPos) {
            if (Math.abs(a - b) <= (rule.within || 8)) return `${rule.a}~${rule.b}`;
          }
        }
      }
      return null;
    }
    return null;
  }

  function matchSignatures(sourceName, strings, context, bytecodeFlags = {}) {
    const hits = [];
    for (const sig of NORMALIZED_SIGS) {
      if (sig.context && !sig.context.includes(context)) continue;
      if (sig.requiresXor && !bytecodeFlags.hasXor) continue;
      if (sig.requiresArrayOps && !bytecodeFlags.hasArrayOps) continue;
      let matched = evalLogic(strings, sig.logic);
      if (matched !== null) {
        if (sig.id === 'webhook_partial') {
          const full = extractDiscordWebhook(strings);
          if (full) matched = full;
        }
        hits.push({
          id: sig.id,
          severity: sig.sev,
          category: sig.cat,
          title: sig.title,
          detail: matched,
          sourceFile: sourceName,
          score: sig.score,
          note: sig.note,
          family: sig.family || '',
        });
      }
    }
    return hits;
  }

  function matchFileSignatures(resourceNames) {
    const hits = [];
    for (const sig of NORMALIZED_SIGS) {
      if (!sig.context || !sig.context.includes('file')) continue;
      for (const fn of resourceNames) {
        const base = fn.split('/').pop();
        const matched = evalLogic([fn, base], sig.logic);
        if (matched !== null) {
          hits.push({
            id: sig.id,
            severity: sig.sev,
            category: sig.cat,
            title: sig.title,
            detail: fn,
            sourceFile: '[resource] ' + fn,
            score: sig.score,
            note: sig.note,
            family: sig.family || '',
          });
        }
      }
    }
    return hits;
  }

  function isBinaryResource(fn) {
    return BINARY_EXTENSIONS.test(fn.split('/').pop());
  }

  function scanBinaryResource(fn, buf) {
    const strings = extractBinaryStrings(buf, 4);
    return matchSignatures('[binary] ' + fn, strings, 'binary').map(h => ({ ...h, sourceFile: '[binary] ' + fn, isBinary: true }));
  }

  function byteEntropy(bytes) {
    const f = new Array(256).fill(0);
    for (const b of bytes) f[b]++;
    let e = 0, n = bytes.length || 1;
    for (const c of f) {
      if (c > 0) {
        const p = c / n;
        e -= p * Math.log2(p);
      }
    }
    return e;
  }

  function obfuscationMetrics(classNames, methodCandidates, classResults) {
    const hits = [];
    let obfCount = 0;
    for (const cn of classNames) {
      const base = cn.split('/').pop().replace('.class', '');
      if (/^[IlO01]{2,}$/.test(base) || base.length <= 2 || /^[a-z][0-9]?$/.test(base)) obfCount++;
    }
    const ratio = classNames.length > 0 ? obfCount / classNames.length : 0;
    if (ratio > 0.5 && classNames.length > 4) {
      hits.push({ id:'obf_high', severity:H, category:'obfusc', family:'Skidfuscator',
        title:`${Math.round(ratio * 100)}% of class names obfuscated (${obfCount}/${classNames.length})`,
        detail:`${obfCount}/${classNames.length} I/l/O/0 or 1-2 char names`, sourceFile:'[structure]',
        score:22, note:'Skidfuscator/Radon naming pattern confirmed by Check Point Research.' });
    } else if (ratio > 0.25 && classNames.length > 3) {
      hits.push({ id:'obf_med', severity:M, category:'obfusc', family:'Obfuscator',
        title:`${Math.round(ratio * 100)}% obfuscated class names`, detail:`${obfCount}/${classNames.length}`,
        sourceFile:'[structure]', score:10, note:'Partial obfuscation.' });
    }

    let idTotal = 0, idSuspicious = 0;
    for (const name of methodCandidates) {
      if (!/^[A-Za-z_$][\w$]*$/.test(name)) continue;
      idTotal++;
      if (/^[a-z]{1,2}$/.test(name) || /^[IlO01]{2,}$/.test(name) || /^(a|b|c|d|e|f|g|h|i|j)$/.test(name)) {
        idSuspicious++;
      }
    }
    const idRatio = idTotal > 0 ? idSuspicious / idTotal : 0;
    if (idRatio > 0.6 && idTotal > 20) {
      hits.push({ id:'obf_methods', severity:H, category:'obfusc', family:'Skidfuscator',
        title:`${Math.round(idRatio * 100)}% obfuscated identifiers (${idSuspicious}/${idTotal})`,
        detail:`${idSuspicious}/${idTotal} short/IlO01 identifiers`, sourceFile:'[structure]',
        score:20, note:'Identifier entropy suggests Skidfuscator/Radon obfuscation.' });
    }

    const avg = classResults.length > 0 ? classResults.reduce((s, cr) => s + (cr.entropy || 0), 0) / classResults.length : 0;
    if (avg > 7.0) {
      hits.push({ id:'entropy_high', severity:H, category:'obfusc', family:'JNIC',
        title:`Very high entropy ${avg.toFixed(2)}/8.0`, detail:`${avg.toFixed(4)} bits/byte across ${classResults.length} files`,
        sourceFile:'[structure]', score:24, note:'Packed/encrypted payloads often exceed 7.0 bits/byte.' });
    } else if (avg > 6.2) {
      hits.push({ id:'entropy_med', severity:M, category:'obfusc', family:'Packed',
        title:`Elevated entropy ${avg.toFixed(2)}/8.0`, detail:avg.toFixed(4),
        sourceFile:'[structure]', score:12, note:'Possible string encryption or compressed payload.' });
    }
    return hits;
  }

  function deduplicate(findings) {
    const seen = new Set();
    return findings.filter(f => {
      const k = (f.id || f.title) + '::' + f.sourceFile;
      if (seen.has(k)) return false;
      seen.add(k);
      return true;
    });
  }

  function detectFamilies(findings) {
    const scores = {};
    for (const f of findings) {
      const fam = f.family || 'Generic';
      const keys = fam.includes('/') ? [fam, ...fam.split('/')] : [fam];
      for (const k of keys) {
        if (!scores[k]) scores[k] = 0;
        scores[k] += (f.score || 0);
      }
    }
    const result = [];
    const seen = new Set();
    for (const [fam, score] of Object.entries(scores).sort((a, b) => b[1] - a[1])) {
      const info = FAMILY_MAP[fam];
      if (!info) continue;
      if (seen.has(info.display)) continue;
      seen.add(info.display);
      result.push({ name: info.display, score, rawFamily: fam });
    }
    return result;
  }

  async function sha256(buf) {
    const h = await crypto.subtle.digest('SHA-256', buf);
    return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('');
  }

  function md5(buf) {
    const bytes = new Uint8Array(buf);
    function add(x, y) { return (x + y) | 0; }
    function rol(n, c) { return (n << c) | (n >>> (32 - c)); }
    function cmn(q, a, b, x, s, t) { return add(rol(add(add(a, q), add(x, t)), s), b); }
    const ff = (a, b, c, d, x, s, t) => cmn((b & c) | (~b & d), a, b, x, s, t);
    const gg = (a, b, c, d, x, s, t) => cmn((b & d) | (c & ~d), a, b, x, s, t);
    const hh = (a, b, c, d, x, s, t) => cmn(b ^ c ^ d, a, b, x, s, t);
    const ii = (a, b, c, d, x, s, t) => cmn(c ^ (b | ~d), a, b, x, s, t);
    const m = [], len = bytes.length;
    for (let i = 0; i < len; i += 4) m[i >> 2] = (bytes[i] || 0) | ((bytes[i + 1] || 0) << 8) | ((bytes[i + 2] || 0) << 16) | ((bytes[i + 3] || 0) << 24);
    m[len >> 2] |= 0x80 << ((len % 4) * 8);
    m[(((len + 8) >> 6) << 4) + 14] = len * 8;
    let a = 1732584193, b = -271733879, c = -1732584194, d = 271733878;
    for (let i = 0; i < m.length; i += 16) {
      const [pa, pb, pc, pd] = [a, b, c, d];
      a = ff(a, b, c, d, m[i], 7, -680876936); d = ff(d, a, b, c, m[i + 1], 12, -389564586); c = ff(c, d, a, b, m[i + 2], 17, 606105819); b = ff(b, c, d, a, m[i + 3], 22, -1044525330);
      a = ff(a, b, c, d, m[i + 4], 7, -176418897); d = ff(d, a, b, c, m[i + 5], 12, 1200080426); c = ff(c, d, a, b, m[i + 6], 17, -1473231341); b = ff(b, c, d, a, m[i + 7], 22, -45705983);
      a = ff(a, b, c, d, m[i + 8], 7, 1770035416); d = ff(d, a, b, c, m[i + 9], 12, -1958414417); c = ff(c, d, a, b, m[i + 10], 17, -42063); b = ff(b, c, d, a, m[i + 11], 22, -1990404162);
      a = ff(a, b, c, d, m[i + 12], 7, 1804603682); d = ff(d, a, b, c, m[i + 13], 12, -40341101); c = ff(c, d, a, b, m[i + 14], 17, -1502002290); b = ff(b, c, d, a, m[i + 15], 22, 1236535329);
      a = gg(a, b, c, d, m[i + 1], 5, -165796510); d = gg(d, a, b, c, m[i + 6], 9, -1069501632); c = gg(c, d, a, b, m[i + 11], 14, 643717713); b = gg(b, c, d, a, m[i], 20, -373897302);
      a = gg(a, b, c, d, m[i + 5], 5, -701558691); d = gg(d, a, b, c, m[i + 10], 9, 38016083); c = gg(c, d, a, b, m[i + 15], 14, -660478335); b = gg(b, c, d, a, m[i + 4], 20, -405537848);
      a = gg(a, b, c, d, m[i + 9], 5, 568446438); d = gg(d, a, b, c, m[i + 14], 9, -1019803690); c = gg(c, d, a, b, m[i + 3], 14, -187363961); b = gg(b, c, d, a, m[i + 8], 20, 1163531501);
      a = gg(a, b, c, d, m[i + 13], 5, -1444681467); d = gg(d, a, b, c, m[i + 2], 9, -51403784); c = gg(c, d, a, b, m[i + 7], 14, 1735328473); b = gg(b, c, d, a, m[i + 12], 20, -1926607734);
      a = hh(a, b, c, d, m[i + 5], 4, -378558); d = hh(d, a, b, c, m[i + 8], 11, -2022574463); c = hh(c, d, a, b, m[i + 11], 16, 1839030562); b = hh(b, c, d, a, m[i + 14], 23, -35309556);
      a = hh(a, b, c, d, m[i + 1], 4, -1530992060); d = hh(d, a, b, c, m[i + 4], 11, 1272893353); c = hh(c, d, a, b, m[i + 7], 16, -155497632); b = hh(b, c, d, a, m[i + 10], 23, -1094730640);
      a = hh(a, b, c, d, m[i + 13], 4, 681279174); d = hh(d, a, b, c, m[i], 11, -358537222); c = hh(c, d, a, b, m[i + 3], 16, -722521979); b = hh(b, c, d, a, m[i + 6], 23, 76029189);
      a = hh(a, b, c, d, m[i + 9], 4, -640364487); d = hh(d, a, b, c, m[i + 12], 11, -421815835); c = hh(c, d, a, b, m[i + 15], 16, 530742520); b = hh(b, c, d, a, m[i + 2], 23, -995338651);
      a = ii(a, b, c, d, m[i], 6, -198630844); d = ii(d, a, b, c, m[i + 7], 10, 1126891415); c = ii(c, d, a, b, m[i + 14], 15, -1416354905); b = ii(b, c, d, a, m[i + 5], 21, -57434055);
      a = ii(a, b, c, d, m[i + 12], 6, 1700485571); d = ii(d, a, b, c, m[i + 3], 10, -1894986606); c = ii(c, d, a, b, m[i + 10], 15, -1051523); b = ii(b, c, d, a, m[i + 1], 21, -2054922799);
      a = ii(a, b, c, d, m[i + 8], 6, 1873313359); d = ii(d, a, b, c, m[i + 15], 10, -30611744); c = ii(c, d, a, b, m[i + 6], 15, -1560198380); b = ii(b, c, d, a, m[i + 13], 21, 1309151649);
      a = ii(a, b, c, d, m[i + 4], 6, -145523070); d = ii(d, a, b, c, m[i + 11], 10, -1120210379); c = ii(c, d, a, b, m[i + 2], 15, 718787259); b = ii(b, c, d, a, m[i + 9], 21, -343485551);
      a = add(a, pa); b = add(b, pb); c = add(c, pc); d = add(d, pd);
    }
    return [a, b, c, d].map(n => (n >>> 0).toString(16).padStart(8, '0').replace(/(..)(..)(..)(..)/g, (_, a, b, c, d) => d + c + b + a)).join('');
  }

  function detectPlatform(zipFiles, resourceNames) {
    if (zipFiles['fabric.mod.json']) return 'Fabric Mod';
    if (zipFiles['plugin.yml']) return 'Bukkit/Spigot Plugin';
    if (zipFiles['bungee.yml']) return 'BungeeCord Plugin';
    if (resourceNames.some(r => r.includes('mods.toml') || r.includes('mcmod.info'))) return 'Forge Mod';
    return 'Java Application';
  }

  const MIXIN_SENSITIVE_METHODS = [
    'MinecraftClient.tick',
    'sendChatMessage',
    'connect',
    'render',
    'handleKeyPress',
    'handleKeyboard',
    'keyPressed',
  ];

  function extractMixinTargets(jsonText) {
    try {
      const data = JSON.parse(jsonText);
      const files = [];
      for (const key of ['mixins', 'client', 'server']) {
        if (Array.isArray(data[key])) files.push(...data[key]);
      }
      const targets = [];
      if (Array.isArray(data.injectors)) {
        for (const inj of data.injectors) {
          const method = inj?.method || inj?.target || '';
          if (method) targets.push(method);
        }
      }
      return { mixins: files, targets };
    } catch (_) {
      return { mixins: [], targets: [] };
    }
  }

  function matchMixinTargets(mixinInfo) {
    const hits = [];
    if (!mixinInfo) return hits;
    const { mixins, targets } = mixinInfo;
    if (Array.isArray(mixins) && mixins.length) {
      hits.push({
        id: 'mixin_present',
        severity: M,
        category: 'loader',
        family: 'Generic loader',
        title: 'Mixin framework detected (mixins.json present)',
        detail: mixins.slice(0, 8).join(', '),
        sourceFile: 'mixins.json',
        score: 10,
        note: 'Mixin usage is normal but can be abused for injection.'
      });
    }
    if (Array.isArray(targets) && targets.length) {
      for (const target of targets) {
        for (const sensitive of MIXIN_SENSITIVE_METHODS) {
          if (String(target).includes(sensitive)) {
            hits.push({
              id: 'mixin_sensitive_inject',
              severity: H,
              category: 'loader',
              family: 'Generic loader',
              title: 'Mixin injection into sensitive method',
              detail: target,
              sourceFile: 'mixins.json',
              score: 38,
              note: 'Mixin injects into sensitive Minecraft methods (tick/chat/connect/render/etc).'
            });
            break;
          }
        }
      }
    }
    return hits;
  }

  async function extractMainClass(zipFiles) {
    const mf = zipFiles['META-INF/MANIFEST.MF'];
    if (!mf) return null;
    const text = await mf.async('string');
    const m = text.match(/Main-Class:\s*(.+)/);
    return m ? m[1].trim() : null;
  }

  function isDangerous(s) {
    for (const d of DANGEROUS) {
      if (s.includes(d)) return true;
    }
    return false;
  }

  return {
    readClassConstants,
    matchSignatures,
    matchFileSignatures,
    scanBinaryResource,
    isBinaryResource,
    extractBinaryStrings,
    obfuscationMetrics,
    deduplicate,
    detectFamilies,
    detectPlatform,
    extractMainClass,
    extractMixinTargets,
    matchMixinTargets,
    sha256,
    md5,
    byteEntropy,
    isDangerous,
    isAllowlistedSha256,
    addAllowlistSha256,
    SIGS: NORMALIZED_SIGS,
    CAT_CONFIG,
  };
})();
