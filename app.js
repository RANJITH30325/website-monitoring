// Telemetry Data Store with Real-World Global Platform Targets
let monitoredTargets = [
    { idToken: "GOG82A", name: "Google Engine Cluster", url: "https://www.google.com", latencyHistory: [71, 65, 82, 59, 74, 68, 71], dnsLookupTime: 12, ttfb: 35, ttlb: 24, expDate: "2027-08-24", checkInterval: "60s", timerId: null, isMuted: false, sessionAlertsCount: 0, currentLiveKbps: 150, totalChecksRun: 15, failedChecksRun: 0, latestTrendDirection: "stable", latestDiagnosticHttpStatusCode: "200 OK" },
    { idToken: "YUT13B", name: "YouTube Global Stream", url: "https://www.youtube.com", latencyHistory: [186, 192, 174, 210, 165, 180, 186], dnsLookupTime: 22, ttfb: 98, ttlb: 66, expDate: "2027-06-15", checkInterval: "60s", timerId: null, isMuted: false, sessionAlertsCount: 0, currentLiveKbps: 420, totalChecksRun: 15, failedChecksRun: 2, latestTrendDirection: "stable", latestDiagnosticHttpStatusCode: "200 OK" },
    { idToken: "MET49A", name: "Facebook Core Network", url: "https://www.facebook.com", latencyHistory: [94, 112, 88, 104, 91, 99, 94], dnsLookupTime: 15, ttfb: 48, ttlb: 31, expDate: "2027-12-15", checkInterval: "60s", timerId: null, isMuted: false, sessionAlertsCount: 0, currentLiveKbps: 210, totalChecksRun: 15, failedChecksRun: 0, latestTrendDirection: "stable", latestDiagnosticHttpStatusCode: "200 OK" },
    { idToken: "WHA70F", name: "WhatsApp Messaging Relay", url: "https://www.whatsapp.com", latencyHistory: [45, 52, 49, 58, 42, 47, 45], dnsLookupTime: 10, ttfb: 30, ttlb: 20, expDate: "2027-05-20", checkInterval: "30s", timerId: null, isMuted: false, sessionAlertsCount: 0, currentLiveKbps: 310, totalChecksRun: 15, failedChecksRun: 0, latestTrendDirection: "stable", latestDiagnosticHttpStatusCode: "200 OK" },
    { idToken: "NET9E3", name: "Netflix Edge Content Delivery", url: "https://www.netflix.com", latencyHistory: [120, 135, 115, 140, 128, 110, 122], dnsLookupTime: 18, ttfb: 75, ttlb: 50, expDate: "2027-11-26", checkInterval: "60s", timerId: null, isMuted: false, sessionAlertsCount: 0, currentLiveKbps: 580, totalChecksRun: 15, failedChecksRun: 0, latestTrendDirection: "stable", latestDiagnosticHttpStatusCode: "200 OK" }
];
let modalSubThroughputChartInstance = null; // Instantly tracks the modal throughput bar chart reference
let modalSubStabilityChartInstance = null;   // Instantly tracks the modal stability pie chart reference
let systemRecycleBin = [];
let isConfigPanelDocked = false; 
let deepHistoryModalChartInstance = null;
let activeInspectedIndexForFilter = null; 
let activeExpandedNodeIdToken = null; // ✅ PERSISTENCE TRACKER: Holds token string to retain state across live pings
// --- Functional Real-time Log Memory Database ---
let systemOperationalLogsMemory = [];
let isLogFeedFrozenActive = false;
let currentSelectedLogSeverityFilter = "ALL";
// --- Found near lines 5 to 6 ---
let currentLogSearchQueryTextString = "";
let isSslRevalidationEngineSyncing = false; // Tracks active certificate revalidation states
let isTurboScanActive = false;
let isFilterStableActive = false;
let isStrictFirewallActive = false; 

const maliciousIntelThreatBlocklist = ["phishing", "exploit", "malware", "trojan", "spyware"];

let globalSystemConfig = {
    latencyThreshold: 200,
    alertLevelTimeThreshold: 130, 
    adultKeywordsThreshold: ["adult", "restricted", "betting", "bypass"], 
    dnsTimeoutThreshold: 25,
    waitingTimeThreshold: 100, 
    voiceProfile: "indian_male",  
    greetingCommand: "standard",  
    globalMute: false
};

let globalGaugeChartInstance = null;
let globalAnalyticsDistributionChartInstance = null; // INJECTED: Manages the Analytics Donut graph instance
let audioEngineActive = false;

// ─── HELPER: compute anomaly priority score for a target (lower = more anomalous) ───
function getAnomalyScore(t) {
    const text = (t.name + " " + t.url).toLowerCase();
    const isThreat = maliciousIntelThreatBlocklist.some(k => text.includes(k));
    const isAdult  = globalSystemConfig.adultKeywordsThreshold.some(k => text.includes(k));
    const isFake   = !t.url.startsWith("http") || t.url.includes("fake") ||
                     t.url.includes("invalid") || t.url.includes("test.xyz") ||
                     isAdult || isThreat;
    const latestLatency = t.latencyHistory[t.latencyHistory.length - 1];
    const isOffline = isFake || latestLatency === 0;
    const sslDays   = Math.ceil((new Date(t.expDate) - new Date()) / (1000 * 60 * 60 * 24));

    if (isThreat)      return 0; // 🔴 Malware / Phishing  → very top
    if (isFake)        return 1; // 🟠 Fake / Invalid domains
    if (isOffline)     return 2; // 🟡 Offline / Unreachable
    if (sslDays <= 0)  return 3; // 🟡 SSL Expired
    if (sslDays <= 30) return 4; // 🟡 SSL Expiring Soon
    return 5;                    // 🟢 Normal / Online → bottom
}

function generateHexTokenIdentification() {
    const hexadecimalCharacters = "0123456789ABCDEF";
    let outputTokenResult = "";
    for (let i = 0; i < 6; i++) {
        outputTokenResult += hexadecimalCharacters[Math.floor(Math.random() * 16)];
    }
    return outputTokenResult;
}

function launchNotificationToast(message, type = "info") {
    const toastCenter = document.getElementById('toast-notification-center');
    if (!toastCenter) return;
    const toastCard = document.createElement('div');
    toastCard.className = `cyber-toast-banner toast-${type}`;
    toastCard.innerHTML = `
        <div class="toast-meta-row"><span>[ SYSTEM_ALERT ]</span><span>${new Date().toLocaleTimeString()}</span></div>
        <div class="toast-msg-body">${message}</div>
    `;
    toastCenter.appendChild(toastCard);
    setTimeout(() => { toastCard.classList.add('slide-in-active'); }, 50);
    setTimeout(() => {
        toastCard.style.transform = "translateX(120%)"; toastCard.style.opacity = "0"; toastCard.style.transition = "all 0.4s ease";
        setTimeout(() => { toastCard.remove(); }, 400);
    }, 4000);
}

function triggerSpeechOutput(alertMessage, targetIndex = null, forceBroadcast = false) {
    if (!forceBroadcast) {
        if (globalSystemConfig.globalMute) return;
        if (targetIndex !== null && monitoredTargets[targetIndex] && monitoredTargets[targetIndex].isMuted) return;
    }
    if (!audioEngineActive) audioEngineActive = true;
    window.speechSynthesis.cancel();
    
    const vocalBroadcastStream = new SpeechSynthesisUtterance(alertMessage);
    const availableSystemVoices = window.speechSynthesis.getVoices();
    
    if (globalSystemConfig.voiceProfile === "indian_female") {
        const indianFemaleMatch = availableSystemVoices.find(v => v.lang.includes("en-IN") && (v.name.toLowerCase().includes("female") || v.name.toLowerCase().includes("heera") || v.name.toLowerCase().includes("priya") || v.name.toLowerCase().includes("google")));
        if (indianFemaleMatch) vocalBroadcastStream.voice = indianFemaleMatch;
        vocalBroadcastStream.rate = 1.0; vocalBroadcastStream.pitch = 1.1;
    } else {
        const indianMaleMatch = availableSystemVoices.find(v => v.lang.includes("en-IN") && (v.name.toLowerCase().includes("male") || v.name.toLowerCase().includes("ravi") || v.name.toLowerCase().includes("mohan")));
        if (indianMaleMatch) vocalBroadcastStream.voice = indianMaleMatch;
        vocalBroadcastStream.rate = 0.95; vocalBroadcastStream.pitch = 0.9;
    }
    window.speechSynthesis.speak(vocalBroadcastStream);
}

window.speechSynthesis.getVoices();
window.speechSynthesis.onvoiceschanged = () => { window.speechSynthesis.getVoices(); };

function toggleBackgroundScroll(disable) {
    if (disable && !isConfigPanelDocked) document.body.classList.add('modal-open');
    else document.body.classList.remove('modal-open');
}

const systemAuthOverlay = document.getElementById('system-auth-overlay');
const initializeSystemBtn = document.getElementById('initialize-system-btn');

// ─── ADVANCED OPERATOR FLOW MESH SEPARATION PERSISTENCE STATE CONFIGS ───
let sequentialAuthFailuresCount = 0;
let systemSecurityLockoutActive = false;
let systemWorkspaceIsUnlocked = false; // 🔒 CRITICAL SECURITY GATE: Silences alerts before initialization

let users = JSON.parse(localStorage.getItem("Website_Monitoring")) || [
    {
        email: "Koushi.yeguru@gmail.com",
        password: "KOUSHIK!"
    }
];
// ─── AUTHENTICATION FLOW FEATURE INTERACTIVE MANAGERS ───
// ─── AUTHENTICATION FLOW FEATURE INTERACTIVE MANAGERS ───
window.toggleAuth = function(mode) {
    if (systemSecurityLockoutActive) {
        launchNotificationToast("Access Denied: Terminal remains frozen under temporary security lockout down due to multiple baseline violation faults.", "alert");
        return;
    }
    const errorBanner = document.getElementById('auth-global-error-banner');
    if (errorBanner) {
        errorBanner.style.display = 'none';
        errorBanner.style.borderColor = '#30363d';
        errorBanner.style.color = '#fff';
    }

    const loginBox = document.getElementById('auth-login-box');
    const registerBox = document.getElementById('auth-register-box');
    const forgotBox = document.getElementById('auth-forgot-box');

    if (loginBox) loginBox.style.display = (mode === 'login') ? 'block' : 'none';
    if (registerBox) registerBox.style.display = (mode === 'register') ? 'block' : 'none';
    if (forgotBox) forgotBox.style.display = (mode === 'forgot') ? 'block' : 'none';

    const captchaBox = document.getElementById('auth-captcha-checkbox');
    if (captchaBox) captchaBox.checked = false;
};

if (initializeSystemBtn && systemAuthOverlay) {
    toggleBackgroundScroll(true);
// 🌐 MATRIX GRID GLOBE ENGINE (3D ROTATING NETWORK TELEMETRY CORE)
    (function runRotatingGlobalMeshHUD() {
        const canvas = document.getElementById('auth-racing-dashboard-cluster');
        if (!canvas) return;
        const ctx = canvas.getContext('2d');
        
        canvas.width = 820;
        canvas.height = 530;
        
        let rotationAngleY = 0;
        let rotationAngleX = 0.3; // Slight tilt for structural depth visualization
        
        // Compile static node coordinates forming a perfect spatial grid sphere
        const spherePoints = [];
        const latitudeLinesCount = 14;
        const longitudeLinesCount = 20;
        const sphereRadius = 160;

        for (let i = 0; i < latitudeLinesCount; i++) {
            const latAngle = (Math.PI * i) / (latitudeLinesCount - 1) - Math.PI / 2;
            for (let j = 0; j < longitudeLinesCount; j++) {
                const lonAngle = (Math.PI * 2 * j) / longitudeLinesCount;
                
                // Convert spherical vectors to 3D Cartesian coordinates
                spherePoints.push({
                    x: sphereRadius * Math.cos(latAngle) * Math.cos(lonAngle),
                    y: sphereRadius * Math.sin(latAngle),
                    z: sphereRadius * Math.cos(latAngle) * Math.sin(lonAngle),
                    isHostNode: Math.random() > 0.92 // Highlights specialized live data centers
                });
            }
        }

       function drawGlobalMesh() {
            // FIX: If display state style value matches none, exit out cleanly without killing future renders
            if (systemAuthOverlay && systemAuthOverlay.style.display === 'none') {
                return;
            }
            ctx.clearRect(0, 0, canvas.width, canvas.height);
            rotationAngleY += 0.006; // Controlled structural rotation tracking velocity
            
            const cx = canvas.width / 2;
            const cy = canvas.height / 2;
            const viewDistance = 400;

            // Project 3D array nodes onto the flat 2D workspace layer
            const projectedPoints = spherePoints.map(p => {
                // 3D Rotation Matrix calculations around Y-axis
                let x1 = p.x * Math.cos(rotationAngleY) - p.z * Math.sin(rotationAngleY);
                let z1 = p.x * Math.sin(rotationAngleY) + p.z * Math.cos(rotationAngleY);
                
                // 3D Rotation Matrix calculations around X-axis
                let y2 = p.y * Math.cos(rotationAngleX) - z1 * Math.sin(rotationAngleX);
                let z2 = p.y * Math.sin(rotationAngleX) + z1 * Math.cos(rotationAngleX);

                // Perspective projection matrix formulations
                const perspectiveScale = viewDistance / (viewDistance + z2);
                return {
                    x: x1 * perspectiveScale + cx,
                    y: y2 * perspectiveScale + cy,
                    z: z2,
                    scale: perspectiveScale,
                    isHostNode: p.isHostNode
                };
            });

            // --- 🕸️ LAYER 1: RENDER CONNECTIVITY LINK MESH LINES ---
            ctx.lineWidth = 0.75;
            ctx.strokeStyle = 'rgba(59, 130, 246, 0.12)';
            
            for (let i = 0; i < projectedPoints.length; i++) {
                // Connect longitudinal neighbors cleanly
                if ((i + 1) % longitudeLinesCount !== 0) {
                    ctx.beginPath();
                    ctx.moveTo(projectedPoints[i].x, projectedPoints[i].y);
                    ctx.lineTo(projectedPoints[i+1].x, projectedPoints[i+1].y);
                    ctx.stroke();
                }
                
                // Connect latitudinal structural rings
                if (i + longitudeLinesCount < projectedPoints.length) {
                    ctx.beginPath();
                    ctx.moveTo(projectedPoints[i].x, projectedPoints[i].y);
                    ctx.lineTo(projectedPoints[i + longitudeLinesCount].x, projectedPoints[i + longitudeLinesCount].y);
                    ctx.stroke();
                }
            }

            // --- 🟢 LAYER 2: DRAW THE ACTIVE NETWORK TELEMETRY DOTS ---
            projectedPoints.forEach(p => {
                // Depth buffer layout: Skip painting deep hidden coordinates to emphasize dimension shifts
                if (p.z > 80) return;

                const baseSize = p.isHostNode ? 4 : 1.5;
                const nodeSize = baseSize * p.scale;
                
                ctx.save();
                ctx.beginPath();
                ctx.arc(p.x, p.y, nodeSize, 0, Math.PI * 2);
                
                if (p.isHostNode) {
                    // Make special monitored host servers flash dynamically
                    const alertPulseGlow = Math.sin(Date.now() * 0.005) * 8 + 10;
                    ctx.fillStyle = '#10b981';
                    ctx.shadowBlur = alertPulseGlow;
                    ctx.shadowColor = '#10b981';
                } else {
                    ctx.fillStyle = 'rgba(59, 130, 246, 0.6)';
                }
                
                ctx.fill();
                ctx.restore();
            });

            // --- 📊 LAYER 3: INNER OSD HUD HUD TEXT LABELS ---
ctx.save(); // Save canvas state to prevent glow from bleeding into other elements
ctx.fillStyle = '#ffffff';

// Modern, clean sans-serif font instead of boring monospace
ctx.font = '900 11px -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif';
ctx.textAlign = 'center';

// Adds futuristic spacing between the letters
ctx.letterSpacing = "3px"; 

// Optional: Add a subtle green glow effect to the text matrix
ctx.shadowColor = '#10b981';
ctx.shadowBlur = 4;

ctx.fillText("WEBSITE MONITORING SYSTEM", cx, cy - 200);
ctx.restore(); // Restore baseline canvas state

            ctx.strokeStyle = 'rgba(0, 0, 0, 0.34)';
            ctx.lineWidth = 1;
            ctx.strokeRect(cx - 100, cy - 222, 200, 32);

            requestAnimationFrame(drawGlobalMesh);
        }
        drawGlobalMesh();
    })();
    // ⌨️ UNIQUE FEATURE EXCLUSIVE: AUTOMATED CAPS-LOCK KEYBOARD INTERACTION DETECTOR
    const passwordInputField = document.getElementById('login-pass');
    passwordInputField?.addEventListener('keyup', (event) => {
        if (systemSecurityLockoutActive) return;
        const errorBanner = document.getElementById('auth-global-error-banner');
        const errorText = document.getElementById('auth-error-text-content');
        
        if (event.getModifierState('CapsLock')) {
            if (errorBanner && errorText) {
                errorText.innerText = "⚠️ SYSTEM HARDWARE WARNING: Caps-Lock is active! Verify character cases to prevent consecutive authentication faults.";
                errorBanner.style.display = 'block';
                errorBanner.style.borderColor = "var(--warning-yellow)";
                errorBanner.style.color = "var(--warning-yellow)";
            }
        } else {
            if (errorBanner && errorText && errorText.innerText.includes("CAPS-LOCK")) {
                errorBanner.style.display = 'none';
            }
        }
    });

    // 🌓 PASSWORD MASK VISIBILITY TOGGLE (EYE ICON INTERACTION FEATURE)
    const togglePasswordMaskBtn = document.getElementById('toggle-password-visibility-btn');
    togglePasswordMaskBtn?.addEventListener('click', (e) => {
        e.preventDefault();
        const passwordField = document.getElementById('login-pass');
        if (!passwordField) return;
        
        if (passwordField.type === 'password') {
            passwordField.type = 'text';
            togglePasswordMaskBtn.innerText = '👁️';
        } else {
            passwordField.type = 'password';
            togglePasswordMaskBtn.innerText = '🙈';
        }
    });

    // 🔒 BRUTE-FORCE PROTECTION: RADIAL TERMINAL TIMEOUT LOCKOUT Lifecycles
    function triggerSecurityLockoutSequence() {
        systemSecurityLockoutActive = true;
        initializeSystemBtn.disabled = true;
        initializeSystemBtn.style.background = "#21262d";
        initializeSystemBtn.style.color = "#8b949e";
        initializeSystemBtn.style.cursor = "not-allowed";
        initializeSystemBtn.innerText = "🔒 SYSTEM LOCKOUT ACTIVE";
        
        let remainingSecondsCount = 25;
        const errorBanner = document.getElementById('auth-global-error-banner');
        const errorText = document.getElementById('auth-error-text-content');
        
        triggerSpeechOutput("Security alert. Too many failed authorization attempts. Access terminal locked down.", null, true);

        const lockoutIntervalWorker = setInterval(() => {
            remainingSecondsCount--;
            if (errorBanner && errorText) {
                errorText.innerText = `🚨 INCORRECT CREDENTIAL VIOLATIONS BREACHED: Terminal interface has frozen. Access capabilities release window countdown: ${remainingSecondsCount}s`;
                errorBanner.style.display = 'block';
                errorBanner.style.borderColor = "var(--pure-red)";
                errorBanner.style.color = "#f87171";
            }
            
            if (remainingSecondsCount <= 0) {
                clearInterval(lockoutIntervalWorker);
                systemSecurityLockoutActive = false;
                sequentialAuthFailuresCount = 0;
                initializeSystemBtn.disabled = false;
                initializeSystemBtn.style.background = "#238636";
                initializeSystemBtn.style.color = "#ffffff";
                initializeSystemBtn.style.cursor = "pointer";
                initializeSystemBtn.innerText = "LOGIN";
                if (errorBanner) errorBanner.style.display = 'none';
                launchNotificationToast("Authentication gateway operational. Session ready.", "info");
            }
        }, 1000);
    }

   // 🔒 SIGN IN ACCESS CONTROLLER INTERCEPT PIPELINE
    initializeSystemBtn.addEventListener('click', (e) => {
        e.preventDefault();
        if (systemSecurityLockoutActive) return;

        const errorBanner = document.getElementById('auth-global-error-banner');
        const errorText = document.getElementById('auth-error-text-content');
        
        const email = document.getElementById('login-email')?.value.trim();
        const pass = document.getElementById('login-pass')?.value.trim();
        const isCaptchaVerified = document.getElementById('auth-captcha-checkbox')?.checked;

        if (!isCaptchaVerified) {
            if (errorBanner && errorText) {
                errorText.innerText = "Security Halt: Please verify that you are an authorized operator (Check 'I'm not a robot').";
                errorBanner.style.display = 'block';
                errorBanner.style.borderColor = "var(--pure-red)";
                errorBanner.style.color = "#f87171";
            }
            launchNotificationToast("Authentication blocked: CAPTCHA missing.", "warning");
            return;
        }

        const foundUser = users.find(user => user.email === email && user.password === pass);
        if (foundUser) {
            if (errorBanner) errorBanner.style.display = 'none';
            audioEngineActive = true;
            systemWorkspaceIsUnlocked = true; // ✅ UNLOCKS NOTIFICATIONS IMMEDIATELY
            
            // DYNAMIC UPDATE: Grabs email username substring if explicit display names aren't mapped
            const derivedOperatorName = foundUser.email.split('@')[0].toUpperCase();
            
            // Updates text label securely preserving the micro layout shield logo
            const profileDisplayElement = document.querySelector(".profile-username-text");
            if (profileDisplayElement) {
                profileDisplayElement.innerText = derivedOperatorName;
            }

            // HIGHLIGHTED ROUND BALL GRAPHIC UPDATE: Pull first string letter token
            const firstLetterChar = derivedOperatorName.charAt(0);
            const letterBallNode = document.getElementById("admin-avatar-letter-ball");
            if (letterBallNode) {
                letterBallNode.innerText = firstLetterChar;
            }

            // INJECT UPDATE: Update Chinnu's structural message greeting bubble right after authorization
            const aiWelcomeBubble = document.querySelector("#chinnu-chat-screen-logs div");
            if (aiWelcomeBubble) {
                aiWelcomeBubble.innerHTML = `👋 Hello <strong>${derivedOperatorName}</strong>! I am connected natively to your live telemetry systems engine. Ask me anything about your current active node metrics or logs memory store profiles.`;
            }

            const cryptoHeader = btoa(JSON.stringify({ alg: "HS256", typ: "JWT" }));
            const cryptoPayload = btoa(JSON.stringify({ operator: email, iss: "WSMS_SECURITY_NODE", scope: "root_admin" }));
            const simulatedJWTString = `${cryptoHeader}.${cryptoPayload}.VERIFIED_SIGNATURE_HASH_TOKEN`;
            console.log(`%c[WSMS AUTH GATEWAY] JWT TRANSMISSION TOKEN EMITTED: ${simulatedJWTString}`, "color: #10b981; font-weight: 900; background: #070a0f; padding: 4px; border: 1px solid #10b981;");
            systemAuthOverlay.style.display = 'none';
            toggleBackgroundScroll(false);

            launchNotificationToast("Welcome Operator. Authentication Successful.", "success");
            triggerSpeechOutput("System access granted. Session validation complete.", null, true);
        } else {
            sequentialAuthFailuresCount++;
            if (sequentialAuthFailuresCount >= 3) {
                triggerSecurityLockoutSequence();
                return;
            }

            if (errorBanner && errorText) {
                errorText.innerText = `Invalid credentials. Attempt [${sequentialAuthFailuresCount}/3] failed. Email/Username not found in temporary sandbox session.`;
                errorBanner.style.display = 'block';
                errorBanner.style.borderColor = "var(--pure-red)";
                errorBanner.style.color = "#f87171";
            }
            launchNotificationToast("Invalid Email or Password Signature.", "alert");
            triggerSpeechOutput("Access denied. Invalid operator credentials signature.", null, true);
        }
    });

    // 🔄 OPERATOR REGISTRATION ENGINE (REAL PERSISTENT LOCAL STORAGE ACCOUNT CREATION)
    const registrationFormElement = document.querySelector('#auth-register-box form');
    registrationFormElement?.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const errorBanner = document.getElementById('auth-global-error-banner');
        const errorText = document.getElementById('auth-error-text-content');
        
        const inputFields = registrationFormElement.querySelectorAll('input');
        const operatorName = inputFields[0]?.value.trim();
        const operatorEmail = inputFields[1]?.value.trim();
        const operatorPassword = inputFields[2]?.value.trim();
        const operatorConfirm = inputFields[3]?.value.trim();

        // Enforce input value validation rules
        if (!operatorEmail || !operatorPassword || !operatorConfirm) {
            launchNotificationToast("Registration blocked: Input values cannot be empty.", "warning");
            return;
        }

        // Validate matching passwords
        if (operatorPassword !== operatorConfirm) {
            if (errorBanner && errorText) {
                errorText.innerText = "⚠️ REGISTRATION ERROR: Security passwords do not correspond. Verify string inputs.";
                errorBanner.style.display = 'block';
                errorBanner.style.borderColor = "var(--pure-red)";
                errorBanner.style.color = "#f87171";
            }
            launchNotificationToast("Passwords mismatch.", "alert");
            return;
        }

        // Prevent duplicate operator account profiles
        const identityCollisionDetected = users.some(u => u.email.toLowerCase() === operatorEmail.toLowerCase());
        if (identityCollisionDetected) {
            if (errorBanner && errorText) {
                errorText.innerText = "⚠️ ACCESS CONTROL VIOLATION: Mapped email identity is already registered to a terminal profile.";
                errorBanner.style.display = 'block';
                errorBanner.style.borderColor = "var(--warning-yellow)";
                errorBanner.style.color = "var(--warning-yellow)";
            }
            launchNotificationToast("Operator profile already exists.", "warning");
            return;
        }

        // Push new user object structure into active memory and local database store
        users.push({ email: operatorEmail, password: operatorPassword });
        localStorage.setItem("Website_Monitoring", JSON.stringify(users));
        
        launchNotificationToast("Operator profile written to database successfully!", "success");
        triggerSpeechOutput("New system administrator credentials compiled successfully.", null, true);
        
        registrationFormElement.reset();
       window.toggleAuth('login');
        // Seamlessly shifts view context back to login form canvas
    });

    // 📬 LIVE ACCESS RECOVERY PIPELINE (DIRECTORY LOOKUP & EMAIL DELIVERY HANDSHAKE)
    const recoverFormElement = document.getElementById('auth-recover-system-form');
    recoverFormElement?.addEventListener('submit', (e) => {
        e.preventDefault();
        
        const errorBanner = document.getElementById('auth-global-error-banner');
        const errorText = document.getElementById('auth-error-text-content');
        const submitButton = document.getElementById('forgot-submit-btn');
        
        const targetRecoveryEmail = document.getElementById('forgot-email')?.value.trim();
        if (!targetRecoveryEmail) return;

        // Directory lookup check: Verify if the user profile exists in your active local users dataset
        const operationalAccountProfile = users.find(u => u.email.toLowerCase() === targetRecoveryEmail.toLowerCase());

        if (!operationalAccountProfile) {
            // Unhide video failure alert banner if email is missing from storage schemas
            if (errorBanner && errorText) {
                errorText.innerText = "❌ ACCESS RECOVERY FAULT: The requested email address could not be verified in our master operator directory.";
                errorBanner.style.display = 'block';
                errorBanner.style.borderColor = "var(--pure-red)";
                errorBanner.style.color = "#f87171";
            }
            launchNotificationToast("Recovery aborted: Unknown operator target.", "alert");
            triggerSpeechOutput("Access recovery rejected. Unknown recipient identity.", null, true);
            return;
        }

        // Generate a real dynamic tracking security verification token key sequence
        const verificationRecoveryTokenKey = "WSMS-" + Math.floor(100000 + Math.random() * 900000);

        // Update interface button display state to indicate request processing status
        if (submitButton) {
            submitButton.disabled = true;
            submitButton.style.background = "#1e293b";
            submitButton.style.color = "#64748b";
            submitButton.innerText = "⚡ ROUTING_DISPATCH_API...";
        }

        // Optional: If you initialize your EmailJS template keys, this block transmits parameters natively
        // emailjs.send("YOUR_SERVICE_ID", "YOUR_TEMPLATE_ID", {
        //     to_email: targetRecoveryEmail,
        //     security_token: verificationRecoveryTokenKey
        // });

        // Fallback network simulation engine loop to cleanly handle interface responses instantly
        setTimeout(() => {
            console.log(`%c[OUTBOUND MAIL CLIENT] PROTOCOL SHA-256 TRANSFERRED TO: ${targetRecoveryEmail}`, "color: #0066ff; font-weight: bold; background: #070a0f; padding: 3px;");
            console.log(`%c[SECURITY REGISTRY] CRYPTO RECOVERY TOKEN KEY GEN: ${verificationRecoveryTokenKey}`, "color: #f59e0b; font-weight: bold;");

            launchNotificationToast(`Verification token code successfully delivered to ${targetRecoveryEmail}!`, "success");
            triggerSpeechOutput("Security token dispatched. Check your communication channels.", null, true);

            // Re-normalize layout state configurations back to baseline values
            if (submitButton) {
                submitButton.disabled = false;
                submitButton.style.background = "#0066ff";
                submitButton.style.color = "#ffffff";
                submitButton.innerText = "DISPATCH RECOVERY LINK";
            }
            
            if (errorBanner) errorBanner.style.display = 'none';
            recoverFormElement.reset();
            window.toggleAuth('login'); // Send user straight back to sign-in panel workspace
        }, 1200);
    });
}
document.addEventListener('click', () => { if (!audioEngineActive) audioEngineActive = true; });

const addSiteModal = document.getElementById('add-site-modal');
const globalParamModal = document.getElementById('global-param-modal');
const recycleBinModal = document.getElementById('recycle-bin-modal');
const deepHistoricalTelemetryModal = document.getElementById('deep-historical-telemetry-modal');
const globalGlassCard = document.getElementById('global-glass-card-element');
const embeddedDockAnchor = document.getElementById('embedded-dock-anchor-slot');
const mainViewportLayoutGrid = document.getElementById('main-viewport-split-matrix');

if (globalGlassCard) {
    globalGlassCard.addEventListener('dblclick', (e) => {
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'SELECT' || e.target.tagName === 'OPTION') return;
        isConfigPanelDocked = !isConfigPanelDocked;
        if (isConfigPanelDocked) {
            embeddedDockAnchor.appendChild(globalGlassCard); globalGlassCard.classList.add('docked-mode'); globalParamModal.classList.remove('active');
            if (mainViewportLayoutGrid) mainViewportLayoutGrid.style.gridTemplateColumns = "2.2fr 1fr";
            document.getElementById('global-header-title-text').innerText = "📌 CORES_DOCKED_CONTROLS";
            document.getElementById('close-global-modal-btn').style.display = "none"; document.getElementById('global-form-actions-footer').style.display = "none";
            triggerSpeechOutput("Global parameters configuration console docked safely inside layout workspace matrix.", null, true);
            launchNotificationToast("Console docked to workspace layouts.", "info");
        } else {
            globalParamModal.appendChild(globalGlassCard); globalGlassCard.classList.remove('docked-mode'); globalParamModal.classList.add('active');
            if (mainViewportLayoutGrid) mainViewportLayoutGrid.style.gridTemplateColumns = "3fr 1fr";
            document.getElementById('global-header-title-text').innerText = "GLOBAL SYSTEM PARAMETERS";
            document.getElementById('close-global-modal-btn').style.display = "block"; document.getElementById('global-form-actions-footer').style.display = "flex";
            triggerSpeechOutput("Configuration console normalized back into overlay layer.", null, true);
            launchNotificationToast("Console restored to window overlays.", "info");
        }
        toggleBackgroundScroll(globalParamModal.classList.contains('active'));
    });
}

if (document.getElementById('open-modal-btn')) {
    document.getElementById('open-modal-btn').addEventListener('click', () => { addSiteModal.classList.add('active'); toggleBackgroundScroll(true); });
}
if (document.getElementById('close-modal-btn')) {
    document.getElementById('close-modal-btn').addEventListener('click', () => { addSiteModal.classList.remove('active'); toggleBackgroundScroll(false); });
}
if (document.getElementById('cancel-modal-btn')) {
    document.getElementById('cancel-modal-btn').addEventListener('click', () => { addSiteModal.classList.remove('active'); toggleBackgroundScroll(false); });
}

if (document.getElementById('close-history-modal-btn')) {
    document.getElementById('close-history-modal-btn').addEventListener('click', () => { deepHistoricalTelemetryModal.classList.remove('active'); toggleBackgroundScroll(false); });
}
if (document.getElementById('close-history-footer-btn')) {
    document.getElementById('close-history-footer-btn').addEventListener('click', () => { deepHistoricalTelemetryModal.classList.remove('active'); toggleBackgroundScroll(false); });
}

if (document.getElementById('close-trash-modal-btn')) {
    document.getElementById('close-trash-modal-btn').addEventListener('click', () => { recycleBinModal.classList.remove('active'); toggleBackgroundScroll(false); });
}
if (document.getElementById('close-trash-footer-btn')) {
    document.getElementById('close-trash-footer-btn').addEventListener('click', () => { recycleBinModal.classList.remove('active'); toggleBackgroundScroll(false); });
}
// --- ADVANCED REAL-TIME SYSTEM LOG ENGINE RENDERER ---
function renderSystemLogsTabUI() {
    if (isLogFeedFrozenActive) return; // Keep rendering frozen for diagnostic inspection shifts

    const logsContainer = document.getElementById('logs-view-container');
    if (!logsContainer) return;

    // Filter operations arrays utilizing dual string matching keywords and status tags
    const outputFilteredDataset = systemOperationalLogsMemory.filter(log => {
        const queryNormalized = currentLogSearchQueryTextString.toLowerCase();
        
        // Comprehensive lookup matching text entries, timestamp metrics, names, and source urls
        const searchMatches = log.text.toLowerCase().includes(queryNormalized) || 
                              log.time.includes(queryNormalized) ||
                              (log.name && log.name.toLowerCase().includes(queryNormalized)) ||
                              (log.url && log.url.toLowerCase().includes(queryNormalized));
        
        let severityMatches = true;
        if (currentSelectedLogSeverityFilter === "NOMINAL") severityMatches = (log.severity === "nominal");
        if (currentSelectedLogSeverityFilter === "ANOMALY") severityMatches = (log.severity === "anomaly");
        if (currentSelectedLogSeverityFilter === "CRITICAL") severityMatches = (log.severity === "critical");

        return searchMatches && severityMatches;
    });

    if (outputFilteredDataset.length === 0) {
        logsContainer.innerHTML = `
            <div style="color: var(--text-muted); text-align:center; padding: 4rem 1rem; font-family: monospace; font-size: 0.75rem; letter-spacing:0.5px;">
                > NO OPERATIONAL RECOGNIZED LOG METRICS MATCH THE ACTIVE COMPONENT FILTERS.
            </div>`;
        return;
    }

    logsContainer.innerHTML = outputFilteredDataset.map(log => {
        let statusAccentBorderColor = "#0066ff";
        let tierLabelText = "CORE";
        let pillBgColor = "rgba(0, 102, 255, 0.12)";
        let pillTextColor = "#3b82f6";

        if (log.severity === "nominal") {
            statusAccentBorderColor = "var(--pure-green)";
            tierLabelText = "INFO";
            pillBgColor = "rgba(16, 185, 129, 0.12)";
            pillTextColor = "var(--pure-green)";
        } else if (log.severity === "anomaly") {
            statusAccentBorderColor = "var(--warning-yellow)";
            tierLabelText = "WARN";
            pillBgColor = "rgba(245, 158, 11, 0.12)";
            pillTextColor = "var(--warning-yellow)";
        } else if (log.severity === "critical") {
            statusAccentBorderColor = "var(--pure-red)";
            tierLabelText = "CRIT";
            pillBgColor = "rgba(239, 68, 68, 0.12)";
            pillTextColor = "var(--pure-red)";
        }

        const cleanNodeLabel = log.name ? log.name.toUpperCase() : "SYSTEM_CORE";
        
        let statusPrefixText = "NOMINAL";
        let prefixColor = "var(--pure-green)";
        
        if (log.severity === "anomaly") {
            statusPrefixText = "REJECTED";
            prefixColor = "var(--warning-yellow)";
        } else if (log.severity === "critical") {
            statusPrefixText = "OUTAGE";
            prefixColor = "var(--pure-red)";
        }

        return `
            <div style="border-left: 4px solid ${statusAccentBorderColor}; background: #0b111e; padding: 0.65rem 0.95rem; border-radius: 4px; font-family: monospace; font-size: 0.74rem; display: flex; gap: 0.6rem; align-items: center; border: 1px solid var(--border-clean); border-left-width: 4px; margin-bottom: 0.25rem;">
                
                <span style="color: var(--text-muted); font-weight: 800; white-space: nowrap; margin-right: 0.3rem;">[${log.time}]</span>
                
                <span style="color: ${prefixColor}; font-weight: 900; white-space: nowrap; font-size: 0.76rem;">${statusPrefixText}:</span>
                
                <span style="color: #ffffff; font-weight: 900; background: rgba(255,255,255,0.02); padding: 0.18rem 0.45rem; border-radius: 3px; border: 1px solid rgba(255,255,255,0.04); max-width: 220px; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; letter-spacing: 0.2px;">
                    ${cleanNodeLabel}
                </span>
                
                <span style="color: var(--pure-blue); font-weight: 900; font-size: 0.85rem; padding: 0 0.1rem;">:</span>
                
                <span style="color: #cbd5e1; flex-grow: 1; text-align: left; line-height: 1.45; padding-left: 0.2rem; font-weight: 500;">
                    ${log.text}
                </span>
                
                <span style="font-size: 0.6rem; padding: 0.12rem 0.45rem; border-radius: 3px; background: ${pillBgColor}; color: ${pillTextColor}; font-weight: 900; letter-spacing: 0.5px; border: 1px solid ${statusAccentBorderColor}30; min-width: 42px; text-align: center; margin-left: 0.5rem;">
                    ${tierLabelText}
                </span>
            </div>
        `;
    }).join('');
}

// --- LOG INTERFACE FEATURE CONTROL ENGINE ACTIONS ---
function initializeLogFeatureControlListeners() {
    const searchFilter = document.getElementById('log-search-filter');
    const severityFilter = document.getElementById('log-severity-filter');
    const freezeBtn = document.getElementById('toggle-log-freeze-btn');
    const clearBtn = document.getElementById('clear-log-memory-btn');

    searchFilter?.addEventListener('input', (e) => {
        currentLogSearchQueryTextString = e.target.value.trim();
        renderSystemLogsTabUI();
    });

    severityFilter?.addEventListener('change', (e) => {
        currentSelectedLogSeverityFilter = e.target.value;
        renderSystemLogsTabUI();
    });

    freezeBtn?.addEventListener('click', () => {
        isLogFeedFrozenActive = !isLogFeedFrozenActive;
        if (isLogFeedFrozenActive) {
            freezeBtn.innerText = "▶️ RESUME_FEED";
            freezeBtn.style.background = "rgba(245, 158, 11, 0.1)";
            freezeBtn.style.color = "var(--warning-yellow)";
            freezeBtn.style.borderColor = "var(--warning-yellow)30";
        } else {
            freezeBtn.innerText = "⏸️ PAUSE_FEED";
            freezeBtn.style.background = "#1e293b";
            freezeBtn.style.color = "#94a3b8";
            freezeBtn.style.borderColor = "var(--border-clean)";
            renderSystemLogsTabUI();
        }
    });

    clearBtn?.addEventListener('click', () => {
        if (confirm("Are you sure you want to flush the real-time operational log cache registry memory?")) {
            systemOperationalLogsMemory = [];
            renderSystemLogsTabUI();
            launchNotificationToast("System tracking logs cleared successfully.", "info");
        }
    });
}
const openGlobalBtn = document.getElementById('open-global-btn');
if (openGlobalBtn && globalParamModal) {
    openGlobalBtn.addEventListener('click', (e) => {
        e.preventDefault();
        if (isConfigPanelDocked) {
            globalGlassCard.scrollIntoView({ behavior: 'smooth' }); globalGlassCard.style.border = "2px solid var(--pure-blue)";
            setTimeout(() => { globalGlassCard.style.border = "1px solid var(--border-clean)"; }, 1200); return;
        }
        const thresholdInput = document.getElementById('global-threshold-input');
        const alertTimeInput = document.getElementById('global-alert-time-input');
        const adultInput = document.getElementById('global-adult-input');
        const dnsTimeoutInput = document.getElementById('global-dns-timeout-input');
        const profileSelect = document.getElementById('global-voice-profile-select');
        const commandSelect = document.getElementById('global-voice-command-select');
        const muteVoiceInput = document.getElementById('global-mute-voice');

        if (thresholdInput) thresholdInput.value = globalSystemConfig.latencyThreshold;
        if (alertTimeInput) alertTimeInput.value = globalSystemConfig.alertLevelTimeThreshold;
        if (adultInput) adultInput.value = globalSystemConfig.adultKeywordsThreshold.join(', ');
        if (dnsTimeoutInput) dnsTimeoutInput.value = globalSystemConfig.dnsTimeoutThreshold;
        if (profileSelect) profileSelect.value = globalSystemConfig.voiceProfile;
        if (commandSelect) commandSelect.value = globalSystemConfig.greetingCommand;
        if (muteVoiceInput) muteVoiceInput.checked = globalSystemConfig.globalMute;
        
        globalParamModal.classList.add('active'); toggleBackgroundScroll(true); 
    });
}

if (document.getElementById('close-global-modal-btn')) {
    document.getElementById('close-global-modal-btn').addEventListener('click', () => { globalParamModal.classList.remove('active'); toggleBackgroundScroll(false); });
}
if (document.getElementById('cancel-global-modal-btn')) {
    document.getElementById('cancel-global-modal-btn').addEventListener('click', () => { globalParamModal.classList.remove('active'); toggleBackgroundScroll(false); });
}

const runLiveGlobalConfigSync = () => {
    const thresholdInput = document.getElementById('global-threshold-input');
    const alertTimeInput = document.getElementById('global-alert-time-input');
    const adultInput = document.getElementById('global-adult-input');
    const dnsTimeoutInput = document.getElementById('global-dns-timeout-input');
    const profileSelect = document.getElementById('global-voice-profile-select');
    const commandSelect = document.getElementById('global-voice-command-select');

    if (thresholdInput) globalSystemConfig.latencyThreshold = parseInt(thresholdInput.value);
    if (alertTimeInput) globalSystemConfig.alertLevelTimeThreshold = parseInt(alertTimeInput.value);
    if (adultInput) globalSystemConfig.adultKeywordsThreshold = adultInput.value.split(',').map(item => item.trim().toLowerCase()).filter(item => item.length > 0);
    if (dnsTimeoutInput) globalSystemConfig.dnsTimeoutThreshold = parseInt(dnsTimeoutInput.value);
    if (profileSelect) globalSystemConfig.voiceProfile = profileSelect.value;
    if (commandSelect) globalSystemConfig.greetingCommand = commandSelect.value;
};

const globalParamForm = document.getElementById('global-param-form');
if (globalParamForm) {
    const muteVoiceInput = document.getElementById('global-mute-voice');
    if (muteVoiceInput) {
        muteVoiceInput.addEventListener('change', (e) => {
            const targetMuteState = e.target.checked; globalSystemConfig.globalMute = targetMuteState;
            if (targetMuteState === true) {
                triggerSpeechOutput("Global telemetry alerts have been silenced.", null, true); launchNotificationToast("Global alerts silenced.", "warning");
            } else {
                triggerSpeechOutput("Global telemetry alerts have been successfully activated.", null, true); launchNotificationToast("Global alerts activated.", "success");
            }
            if (isConfigPanelDocked) { renderDashboardUI(); }
        });
    }

    globalParamForm.querySelectorAll('input:not(#global-mute-voice), select').forEach(element => {
        element.addEventListener('change', () => { runLiveGlobalConfigSync(); if (isConfigPanelDocked) { renderDashboardUI(); } });
    });
    globalParamForm.addEventListener('submit', (e) => {
        e.preventDefault(); runLiveGlobalConfigSync();
        triggerSpeechOutput("Voice profile configuration parameters deployed successfully.", null, true); launchNotificationToast("Parameters successfully updated.", "success");
        globalParamModal.classList.remove('active'); toggleBackgroundScroll(false); renderDashboardUI();
    });
}

if (document.getElementById('open-trash-btn')) {
    document.getElementById('open-trash-btn').addEventListener('click', () => { renderRecycleBinList(); if (recycleBinModal) { recycleBinModal.classList.add('active'); toggleBackgroundScroll(true); } });
}

const globalTurboModeCheckbox = document.getElementById('global-turbo-mode-checkbox');
const globalFilterStableCheckbox = document.getElementById('global-filter-stable-checkbox');
const globalStrictFirewallCheckbox = document.getElementById('global-strict-firewall-checkbox'); 

if (globalTurboModeCheckbox) {
    globalTurboModeCheckbox.addEventListener('change', (e) => {
        isTurboScanActive = e.target.checked;
        if (isTurboScanActive) {
            triggerSpeechOutput("Turbo scan mode activated. Forcing network check intervals to 5 seconds.", null, true); launchNotificationToast("Turbo scan activated: 5s polling.", "warning");
        } else {
            triggerSpeechOutput("Turbo scan mode deactivated. Restoring localized loop timelines.", null, true); launchNotificationToast("Turbo scan deactivated. Restoring defaults.", "info");
        }
        monitoredTargets.forEach((_, idx) => startTargetWorkerSchedule(idx));
        renderDashboardUI();
    });
}

if (globalFilterStableCheckbox) {
    globalFilterStableCheckbox.addEventListener('change', (e) => {
        isFilterStableActive = e.target.checked;
        if (isFilterStableActive) {
            triggerSpeechOutput("Filtering active profiles. System will only vocalize network anomaly logs.", null, true); launchNotificationToast("Mute Stable Nodes active.", "warning");
        } else {
            triggerSpeechOutput("Filtering deactivated. All telemetry paths open.", null, true); launchNotificationToast("All vocal tracks open.", "success");
        }
    });
}

if (globalStrictFirewallCheckbox) {
    globalStrictFirewallCheckbox.addEventListener('change', (e) => {
        isStrictFirewallActive = e.target.checked;
        if (isStrictFirewallActive) {
            triggerSpeechOutput("Strict security firewall active. Isolating loops on all restricted endpoints.", null, true); launchNotificationToast("Strict Firewall Mode activated.", "alert");
        } else {
            triggerSpeechOutput("Firewall isolation disabled. Re-opening network lanes.", null, true); launchNotificationToast("Strict Firewall Mode deactivated.", "success");
        }
        monitoredTargets.forEach((_, idx) => startTargetWorkerSchedule(idx));
        renderDashboardUI();
    });
}

const addSiteForm = document.getElementById('add-site-form');
if (addSiteForm) {
    addSiteForm.addEventListener('submit', (e) => {
        e.preventDefault();
        const name = document.getElementById('site-name-input').value; const url = document.getElementById('site-url-input').value; const selectedInterval = document.getElementById('site-interval-input').value;
        const computedExpDate = new Date(); const combinedStringToCheck = (name + " " + url).toLowerCase();
        
        const hitsAdultContentThreshold = globalSystemConfig.adultKeywordsThreshold.some(keyword => combinedStringToCheck.includes(keyword));
        const hitsThreatIntelBlocklist = maliciousIntelThreatBlocklist.some(keyword => combinedStringToCheck.includes(keyword));

        let isFakeDetected = url.includes("fake") || url.includes("invalid") || url.includes("test.xyz") || (!url.startsWith("http://") && !url.startsWith("https://"));
        if (hitsAdultContentThreshold || isFakeDetected || hitsThreatIntelBlocklist) computedExpDate.setDate(computedExpDate.getDate() - 1);
        else computedExpDate.setDate(computedExpDate.getDate() + Math.floor(Math.random() * 70) + 15);

        const newTarget = {
            idToken: generateHexTokenIdentification(),
            name: name, url: url, latencyHistory: [100, 110, 95, 120, 130, 105, 115],
            dnsLookupTime: 15, ttfb: 45, ttlb: 35, expDate: computedExpDate.toISOString().split('T')[0],
            checkInterval: selectedInterval, timerId: null, isMuted: false, isAdultBlocked: hitsAdultContentThreshold, sessionAlertsCount: 0, currentLiveKbps: 120, totalChecksRun: 1, failedChecksRun: 0, latestTrendDirection: "stable", latestDiagnosticHttpStatusCode: "200 OK"
        };

        monitoredTargets.push(newTarget); addSiteModal.classList.remove('active'); toggleBackgroundScroll(false); addSiteForm.reset();
        
        if (hitsThreatIntelBlocklist) { triggerSpeechOutput(`Security exception. Network packet block deployment isolated critical exploitation vector on ${name}.`, null, true); launchNotificationToast(`Threat-Intel Core Blocked: ${name}`, "alert"); }
        else if (isFakeDetected) { triggerSpeechOutput(`Security warning. Fake target host profile detected for ${name}. Isolating probe channel.`, null, true); launchNotificationToast(`Fake Signature Rejected: ${name}`, "alert"); }
        else if (hitsAdultContentThreshold) { triggerSpeechOutput(`Security Exception. Adult filter violation blocked traffic on ${name}.`, null, true); launchNotificationToast(`Content Filter Violation: ${name}`, "alert"); }
        else { triggerSpeechOutput(`New endpoint probe deployed for ${name}.`, null, true); launchNotificationToast(`Probe online: ${name}`, "success"); }

        startTargetWorkerSchedule(monitoredTargets.length - 1); renderDashboardUI();
    });
}

if (document.getElementById('refresh-btn')) {
    document.getElementById('refresh-btn').addEventListener('click', () => { monitoredTargets.forEach((_, idx) => { if (monitoredTargets[idx].checkInterval !== "none") executeSingleProbeCheck(idx); }); });
}

function parseIntervalToMs(intervalStr) {
    if (isTurboScanActive) return 5000; 
    if (intervalStr === "30s") return 30000; if (intervalStr === "60s") return 60000; if (intervalStr === "1min") return 60000;
    if (intervalStr === "5min") return 300000; if (intervalStr === "10min") return 600000; if (intervalStr === "30min") return 1800000;
    return 0;
}

function startTargetWorkerSchedule(idx) {
    const target = monitoredTargets[idx]; if (target.timerId) clearInterval(target.timerId); 
    
    const textSignature = (target.name + " " + target.url).toLowerCase();
    const isViolatedNode = globalSystemConfig.adultKeywordsThreshold.some(keyword => textSignature.includes(keyword)) || maliciousIntelThreatBlocklist.some(keyword => textSignature.includes(keyword));
    
    if (isStrictFirewallActive && isViolatedNode) return; 
    if (target.checkInterval === "none" && !isTurboScanActive) return;
    
    target.timerId = setInterval(() => { executeSingleProbeCheck(idx); }, parseIntervalToMs(target.checkInterval));
}

function executeSingleProbeCheck(idx) {
    const target = monitoredTargets[idx]; if (!target) return;
    const validationString = (target.name + " " + target.url).toLowerCase();
    
    target.isAdultBlocked = globalSystemConfig.adultKeywordsThreshold.some(keyword => validationString.includes(keyword));
    const hitsThreatIntelBlocklist = maliciousIntelThreatBlocklist.some(keyword => validationString.includes(keyword));

    const precedingLatencySample = target.latencyHistory[target.latencyHistory.length - 1];

    let isFakeOrInvalid = !target.url.startsWith("http://") && !target.url.startsWith("https://") || target.url.includes("fake") || target.url.includes("invalid") || target.url.includes("test.xyz") || target.isAdultBlocked || hitsThreatIntelBlocklist;
    let aliveState = !isFakeOrInvalid && (Math.random() > 0.12);
    let dnsLookup = isFakeOrInvalid ? Math.floor(Math.random() * 20) + 40 : Math.floor(Math.random() * 12) + 6;
    let ttfbTime = isFakeOrInvalid ? 0 : Math.floor(Math.random() * 60) + 30; let ttlbTime = isFakeOrInvalid ? 0 : Math.floor(Math.random() * 50) + 20;
    
    if (Math.random() > 0.82 && !isFakeOrInvalid) dnsLookup = Math.floor(Math.random() * 20) + 35; 
    if (Math.random() > 0.82 && !isFakeOrInvalid) ttfbTime = Math.floor(Math.random() * 60) + 110; 

    let totalLatency = dnsLookup + ttfbTime + ttlbTime;
    if (isFakeOrInvalid || !aliveState) totalLatency = 0;

    target.latencyHistory.shift(); target.latencyHistory.push(totalLatency);
    target.dnsLookupTime = dnsLookup; target.ttfb = ttfbTime; target.ttlb = ttlbTime;
    
    if (target.checkInterval !== "none" || isTurboScanActive) {
        // 🛑 HALT: Silently return and block alerts if user hasn't successfully signed in yet
        if (!systemWorkspaceIsUnlocked) return;

        const remainingDaysLeft = Math.ceil((new Date(target.expDate) - new Date()) / (1000 * 60 * 60 * 24));
        const hasSslAlertTriggered = !isFakeOrInvalid && (remainingDaysLeft <= 30);
        
        const logTimestamp = new Date().toLocaleTimeString();
        let logMessageText = `Probe check executed for ${target.name}. Response Code: ${target.latestDiagnosticHttpStatusCode}.`;
        let logSeverityTag = "nominal";
        if (hitsThreatIntelBlocklist) {
            target.sessionAlertsCount++;
            logMessageText = `Threat-Intel core isolation deployment dropped malicious payload rules connection sequence safely.`;
            logSeverityTag = "critical";
            triggerSpeechOutput(`Security firewall exception. Malicious IP endpoint network vector blocked on ${target.name}.`, idx); 
            launchNotificationToast(`MALWARE THREAT BLOCKED: ${target.name}`, "alert");
        } else if (target.isAdultBlocked) {
            target.sessionAlertsCount++;
            logMessageText = `Content proxy filter rules matched restricted profile parameters (HTTP 403 Access Revoked).`;
            logSeverityTag = "critical";
            triggerSpeechOutput(`Security Exception. Adult filter violation blocked traffic on ${target.name}. Code 403.`, idx); 
            launchNotificationToast(`${target.name}: HTTP 403 Forbidden`, "alert");
        } else if (isFakeOrInvalid) {
            logMessageText = `Ghost node layout mapping verified dead or invalid domain target signature schema parameters.`;
            logSeverityTag = "anomaly";
            if (Math.random() > 0.75) { 
                target.sessionAlertsCount++;
                triggerSpeechOutput(`Alert. Fake target signature active on channel ${target.name}.`, idx); 
                launchNotificationToast(`${target.name}: HTTP ${target.latestDiagnosticHttpStatusCode}`, "alert");
            }
        } else if (!aliveState) {
            target.sessionAlertsCount++;
            logMessageText = `High-availability cluster heartbeat broken. Probe request dropped with error code: ${target.latestDiagnosticHttpStatusCode}.`;
            logSeverityTag = "critical";
            triggerSpeechOutput(`Alert. Critical outage detected on ${target.name}. Response code ${target.latestDiagnosticHttpStatusCode.split(' ')[0]}.`, idx); 
            launchNotificationToast(`CRITICAL: ${target.name} returned ${target.latestDiagnosticHttpStatusCode}`, "alert");
        } else if (hasSslAlertTriggered) {
            target.sessionAlertsCount++;
            logSeverityTag = "anomaly";
            if (remainingDaysLeft <= 0) {
                logMessageText = `Handshake transport authorization keys have fully lapsed. Global network boundary rules deployed.`;
                logSeverityTag = "critical";
                triggerSpeechOutput(`Security alert. SSL certificate for ${target.name} has expired. Deploy renewal keys immediately.`, idx);
                launchNotificationToast(`CRITICAL SECURITY: ${target.name} SSL EXPIRED`, "alert");
            } else {
                logMessageText = `TLS security encryption layers aging out. Encryption certificate keys expire inside a window of ${remainingDaysLeft} days.`;
                triggerSpeechOutput(`Security notice. Certificate for ${target.name} expires in ${remainingDaysLeft} days.`, idx);
                launchNotificationToast(`SSL WARNING: ${target.name} certificate expiring soon`, "warning");
            }
        } else if (aliveState) {
            const isAnomalyState = (dnsLookup > globalSystemConfig.dnsTimeoutThreshold) ||
                (totalLatency > globalSystemConfig.latencyThreshold) || (ttfbTime > globalSystemConfig.waitingTimeThreshold) || (totalLatency >= globalSystemConfig.alertLevelTimeThreshold);
            
            if (dnsLookup > globalSystemConfig.dnsTimeoutThreshold) { 
                target.sessionAlertsCount++;
                logMessageText = `Elevated core network layer domain lookup resolution delays measured over standard thresholds (${dnsLookup}ms).`;
                logSeverityTag = "anomaly";
                triggerSpeechOutput(`Warning. High DNS lookup time anomaly detected on ${target.name}.`, idx); 
                launchNotificationToast(`${target.name}: DNS Anomaly Detected`, "warning");
            }
            else if (totalLatency > globalSystemConfig.latencyThreshold) { 
                target.sessionAlertsCount++;
                logMessageText = `Round-trip network delay latency limits breached. High processing strain observed (${totalLatency}ms total latency).`;
                logSeverityTag = "critical";
                triggerSpeechOutput(`Alert. Network latency threshold breached on ${target.name}.`, idx); 
                launchNotificationToast(`${target.name}: Latency Threshold Breached`, "alert");
            }
            else if (ttfbTime > globalSystemConfig.waitingTimeThreshold) { 
                target.sessionAlertsCount++;
                logMessageText = `Elevated Time-To-First-Byte waiting thresholds caught during socket interface query cycle (${ttfbTime}ms TTFB).`;
                logSeverityTag = "anomaly";
                triggerSpeechOutput(`Notice. High response waiting time detected on ${target.name}.`, idx); 
                launchNotificationToast(`${target.name}: High Response Waiting Time`, "warning");
            }
            else if (totalLatency >= globalSystemConfig.alertLevelTimeThreshold) { 
                target.sessionAlertsCount++;
                logMessageText = `Performance deviation metrics drifting away from baseline values (${totalLatency}ms response runtime cycle).`;
                logSeverityTag = "anomaly";
                triggerSpeechOutput(`Notice. Performance warning threshold level reached on ${target.name}.`, idx); 
                launchNotificationToast(`${target.name}: Performance Warning`, "warning");
            }
            
            if (!isAnomalyState) {
                logMessageText = `Active data channels nominal. Stable connectivity pipelines executing processing logic successfully (${totalLatency}ms).`;
                logSeverityTag = "nominal";
                if (!isFilterStableActive && Math.random() > 0.85) { 
                    triggerSpeechOutput(`${target.name} operational. Response code 200.`, idx);
                }
            }
        }

        // Push new historical logging metadata tracking frames into global session storage
        systemOperationalLogsMemory.unshift({ 
            time: logTimestamp, 
            text: logMessageText, 
            severity: logSeverityTag,
            name: target.name, // Explicitly saved for search box indexing
            url: target.url    // Explicitly saved for search box indexing
        });
        if (systemOperationalLogsMemory.length > 120) systemOperationalLogsMemory.pop();
    }

    // Refresh display layout pipelines depending on what layout screen user is on
    if (currentActiveTabContext === "monitoring logs") {
        renderSystemLogsTabUI();
    } else if (currentActiveTabContext === "analytics") {
        renderAnalyticsTabUI(); // FIXED: Dynamically re-runs calculations on every live ping!
    } else {
        renderDashboardUI();
    }
    
    if (deepHistoricalTelemetryModal.classList.contains('active') && activeInspectedIndexForFilter === idx) {
        updateHistoricalChartWithFilter();
    }
}

function renderRecycleBinList() {
    const container = document.getElementById('trash-list-container'); if (!container) return;
    if (systemRecycleBin.length === 0) { container.innerHTML = `<p style="color: var(--text-muted); text-align:center; padding: 1rem; font-size: 0.9rem;">> Trash register clear. Zero archived nodes detected.</p>`; return; }

    let trashListMarkup = `
        <div style="display: flex; gap: 0.75rem; align-items: center; background: rgba(0,0,0,0.06); padding: 0.6rem; border-radius: 4px; margin-bottom: 1rem; border: 1px solid var(--border-clean);">
            <input type="checkbox" id="mass-trash-select-all" style="width: 16px; height: 16px; cursor: pointer;">
            <span style="font-size: 0.8rem; font-weight: 700; color: var(--text-primary); margin-right: auto;">Select All</span>
            <button id="mass-restore-btn" style="background: var(--pure-green); color: white; border: none; padding: 0.35rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; cursor: pointer;">🔄 Restore</button>
            <button id="mass-delete-btn" style="background: var(--pure-red); color: white; border: none; padding: 0.35rem 0.75rem; border-radius: 4px; font-size: 0.75rem; font-weight: 700; cursor: pointer;">🗑️ Delete Permanently</button>
        </div><div id="inner-trash-items-wrapper">
    `;
    trashListMarkup += systemRecycleBin.map((site, index) => `
        <div style="display: flex; gap: 0.8rem; align-items: center; border-bottom: 1px solid var(--border-clean); padding: 0.6rem 0.4rem;">
            <input type="checkbox" class="individual-trash-checkbox" data-trash-idx="${index}" style="width: 16px; height: 16px; cursor: pointer;">
            <div style="flex-grow: 1; margin-left: 0.2rem;">
                <div style="font-family: monospace; font-size: 0.7rem; color: var(--text-muted); font-weight: 800; margin-bottom: 0.1rem;">[ARCHIVED_ID: #${site.idToken}]</div>
                <strong style="color: var(--text-primary); font-size: 0.9rem;">${site.name}</strong>
                <div style="color: var(--text-muted); font-size: 0.75rem; font-family: monospace;">${site.url}</div>
            </div>
        </div>
    `).join('');
    trashListMarkup += `</div>`; container.innerHTML = trashListMarkup;

    const selectAllCheckbox = document.getElementById('mass-trash-select-all'); const individualCheckboxes = container.querySelectorAll('.individual-trash-checkbox');
    if (selectAllCheckbox) { selectAllCheckbox.addEventListener('change', (e) => { const isChecked = e.target.checked; individualCheckboxes.forEach(cb => cb.checked = isChecked); }); }

    document.getElementById('mass-restore-btn').addEventListener('click', () => {
        let itemsToRestore = []; individualCheckboxes.forEach(cb => { if (cb.checked) itemsToRestore.push(parseInt(cb.getAttribute('data-trash-idx'))); });
        if (itemsToRestore.length === 0) return;
        itemsToRestore.sort((a, b) => b - a).forEach(idx => { const restoredSite = systemRecycleBin.splice(idx, 1)[0]; monitoredTargets.push(restoredSite); startTargetWorkerSchedule(monitoredTargets.length - 1); });
        triggerSpeechOutput("Selected items recovered and returned to active monitoring mesh.", null, true); launchNotificationToast("Batch nodes restored successfully.", "success"); syncRecycleBinCountUI();
    });

    document.getElementById('mass-delete-btn').addEventListener('click', () => {
        let itemsToDelete = []; individualCheckboxes.forEach(cb => { if (cb.checked) itemsToDelete.push(parseInt(cb.getAttribute('data-trash-idx'))); });
        if (itemsToDelete.length === 0) return;
        itemsToDelete.sort((a, b) => b - a).forEach(idx => { systemRecycleBin.splice(idx, 1); });
        triggerSpeechOutput("Selected items permanently deleted from history.", null, true); launchNotificationToast("Batch targets deleted permanently.", "warning"); syncRecycleBinCountUI();
    });
}

function syncRecycleBinCountUI() {
    if (document.getElementById('trash-count')) document.getElementById('trash-count').innerText = systemRecycleBin.length;
    renderRecycleBinList(); renderDashboardUI();
}

function updateHistoricalChartWithFilter() {
    if (activeInspectedIndexForFilter === null) return;
    const target = monitoredTargets[activeInspectedIndexForFilter];
    if (!target) return;

    const filterSelector = document.getElementById('deep-history-range-filter');
    const recordsToSliceCount = filterSelector ? parseInt(filterSelector.value) : 7;

    const activeLatencyDataSlice = target.latencyHistory.slice(-recordsToSliceCount);

    let timelineLabels = [];
    for (let i = activeLatencyDataSlice.length - 1; i >= 0; i--) {
        timelineLabels.push(i === 0 ? 'Live Check' : `T-${i}`);
    }

    const canvasContext = document.getElementById('deepHistoryModalLineChart').getContext('2d');
    if (deepHistoryModalChartInstance) deepHistoryModalChartInstance.destroy();

    deepHistoryModalChartInstance = new Chart(canvasContext, {
        type: 'line',
        data: {
            labels: timelineLabels,
            datasets: [{
                label: `Response Delay (Last ${recordsToSliceCount} Probes)`,
                data: activeLatencyDataSlice,
                borderColor: '#0066ff',
                backgroundColor: 'rgba(0, 102, 255, 0.04)',
                borderWidth: 3,
                pointRadius: 4,
                pointBackgroundColor: '#000000',
                tension: 0.25,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: true, labels: { boxWidth: 12, font: { weight: 'bold' } } } },
            scales: {
                x: { grid: { display: true, color: 'rgba(0,0,0,0.03)' } },
                y: { display: true, min: 0, title: { display: true, text: 'Latency Speed (ms)', font: { size: 10, weight: 'bold' } } }
            }
        }
    });
}

function openDeepHistoryDiagnosticPanel(idx) {
    const target = monitoredTargets[idx]; if (!target) return;
    activeInspectedIndexForFilter = idx;
    const validSamples = target.latencyHistory.filter(v => v > 0);
    const avgLatency = validSamples.length > 0 ? (validSamples.reduce((a, b) => a + b, 0) / validSamples.length) : 0;
    const latencyVariance = validSamples.length > 0 ? Math.round(Math.sqrt(validSamples.reduce((acc, val) => acc + Math.pow(val - avgLatency, 2), 0) / validSamples.length)) : 0;
    const missingPackets = target.latencyHistory.filter(v => v === 0).length;
    const uptimePercentage = Math.round(((target.latencyHistory.length - missingPackets) / target.latencyHistory.length) * 100);
    
    // Dynamic title assignment text nodes compilation
    const titleTextNode = document.getElementById('history-modal-site-title');
    if (titleTextNode) {
        titleTextNode.innerText = `[NODE_ID: #${target.idToken}] // ${target.name.toUpperCase()}`;
    }

    // Safely configure overlay listener configurations
    const rangeFilterInput = document.getElementById('deep-history-range-filter');
    if (rangeFilterInput) {
        rangeFilterInput.onchange = () => { updateHistoricalChartWithFilter(); };
    }

    const closeBtnNode = document.getElementById('close-history-modal-btn');
    if (closeBtnNode) {
        closeBtnNode.onclick = () => { deepHistoricalTelemetryModal.classList.remove('active'); toggleBackgroundScroll(false); };
    }

    if (document.getElementById('history-modal-uptime-val')) document.getElementById('history-modal-uptime-val').innerText = `${uptimePercentage}%`;
    if (document.getElementById('history-modal-variance-val')) document.getElementById('history-modal-variance-val').innerText = `${latencyVariance} ms`;
    if (document.getElementById('history-modal-alerts-count')) document.getElementById('history-modal-alerts-count').innerText = target.sessionAlertsCount || 0;

    deepHistoricalTelemetryModal.classList.add('active');
    toggleBackgroundScroll(true);
    updateHistoricalChartWithFilter();

    // ─── FEATURE PLOT A: LIVE THROUGHPUT HORIZONTAL VELOCITY GRAPH ───
    const throughputCanvas = document.getElementById("modalSubThroughputBarChart");
    if (throughputCanvas) {
        if (modalSubThroughputChartInstance) modalSubThroughputChartInstance.destroy();
        modalSubThroughputChartInstance = new Chart(throughputCanvas.getContext('2d'), {
            type: 'bar',
            data: {
                labels: ['Current Live Load'],
                datasets: [{
                    data: [target.currentLiveKbps || 120],
                    backgroundColor: 'rgba(0, 240, 255, 0.4)',
                    borderColor: '#00f0ff',
                    borderWidth: 1.5,
                    borderRadius: 4,
                    barThickness: 15
                }]
            },
            options: {
                indexAxis: 'y',
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { display: false } },
                scales: {
                    x: { beginAtZero: true, grid: { color: 'rgba(255,255,255,0.05)' }, ticks: { color: '#94a3b8', font: { size: 8 } } },
                    y: { display: false }
                }
            }
        });
    }

    // ─── FEATURE PLOT B: STABILITY HEARTBEAT PACKET DISTRIBUTION PIE ───
    const stabilityCanvas = document.getElementById("modalSubStabilityPieChart");
    if (stabilityCanvas) {
        if (modalSubStabilityChartInstance) modalSubStabilityChartInstance.destroy();
        const successPacketsCount = target.latencyHistory.length - missingPackets;
        modalSubStabilityChartInstance = new Chart(stabilityCanvas.getContext('2d'), {
            type: 'doughnut',
            data: {
                labels: ['OK', 'DROP'],
                datasets: [{
                    data: [successPacketsCount, missingPackets],
                    backgroundColor: ['#10b981', '#ef4444'],
                    borderColor: '#151f32',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: { legend: { position: 'right', labels: { color: '#94a3b8', font: { size: 8, family: 'monospace' } } } },
                cutout: '60%'
            }
        });
    }
}

// Global tracking state variable to manage row filtration indices across views
let currentActiveTabContext = "dashboard";
let dashboardOverviewChartInstance = null;

// ─── CENTRALIZED TAB NAVIGATION ENGINE & INITIALIZER ───
document.addEventListener("DOMContentLoaded", () => {
    const menuLinks = document.querySelectorAll(".menu-link");
    const dynamicMainTitle = document.querySelector(".brand-matrix h1");
    
    const administrationDock = document.querySelector(".bulk-administration-dock");
    const summaryCountersMatrix = document.querySelector(".summary-matrix");
    const listMeshSplitViewport = document.getElementById("main-viewport-split-matrix");
    const dashboardGridFeatureElement = document.querySelector(".dashboard-features-grid");

    // Force application initial setup parameters to sync correctly on page load
    currentActiveTabContext = "dashboard";
    if (dynamicMainTitle) dynamicMainTitle.innerHTML = `Dashboard`;
    
    administrationDock?.classList.add("view-hidden-state");
    summaryCountersMatrix?.classList.add("view-hidden-state"); // Changed to hide on dashboard load
    listMeshSplitViewport?.classList.add("view-hidden-state");   // Changed to hide on dashboard load
    dashboardGridFeatureElement?.classList.remove("view-hidden-state");

    menuLinks.forEach(link => {
        link.addEventListener("click", (e) => {
            e.preventDefault();

            link.classList.add("menu-link-pulse");
            link.addEventListener("animationend", () => {
                link.classList.remove("menu-link-pulse");
            }, { once: true });

            menuLinks.forEach(item => item.classList.remove("active-link"));
            link.classList.add("active-link");

            // Simplified string containment check to prevent route mismatch bugs
            const rawButtonText = link.textContent.toLowerCase();
            
            if (dynamicMainTitle) {
                dynamicMainTitle.innerHTML = `${link.innerHTML}`;
            }

          // 5. Context UI Element Filter Router Box (Multi-View Visibility Manager)
            const monitoringLogsView = document.getElementById("monitoring-logs-view");
            const sslMonitoringView = document.getElementById("ssl-monitoring-view");
            const analyticsView = document.getElementById("analytics-view"); // FETCHED THE ANALYTICS ELEMENT
            
            // Hide custom sub-views by default to clear canvas workspace safely and cleanly
            monitoringLogsView?.classList.add("view-hidden-state");
            sslMonitoringView?.classList.add("view-hidden-state");
            analyticsView?.classList.add("view-hidden-state"); // FIXED: Forces the analytics tab to hide when leaving!

            if (rawButtonText.includes("dashboard")) {
                currentActiveTabContext = "dashboard";
                administrationDock?.classList.add("view-hidden-state");
                summaryCountersMatrix?.classList.add("view-hidden-state");
                listMeshSplitViewport?.classList.add("view-hidden-state");
                dashboardGridFeatureElement?.classList.remove("view-hidden-state");
                setTimeout(() => { initializeDashboardPerformanceChart(); }, 20);
            } 
            else if (rawButtonText.includes("websites")) {
                currentActiveTabContext = "websites";
                administrationDock?.classList.remove("view-hidden-state");
                summaryCountersMatrix?.classList.remove("view-hidden-state");
                listMeshSplitViewport?.classList.remove("view-hidden-state");
                dashboardGridFeatureElement?.classList.add("view-hidden-state");
            } 
            else if (rawButtonText.includes("monitoring logs")) {
                currentActiveTabContext = "monitoring logs";
                administrationDock?.classList.add("view-hidden-state");
                summaryCountersMatrix?.classList.add("view-hidden-state");
                listMeshSplitViewport?.classList.add("view-hidden-state");
                dashboardGridFeatureElement?.classList.add("view-hidden-state");
                
                monitoringLogsView?.classList.remove("view-hidden-state");
                renderSystemLogsTabUI();
            }
            else if (rawButtonText.includes("ssl monitoring")) {
                currentActiveTabContext = "ssl monitoring";
                administrationDock?.classList.add("view-hidden-state");
                summaryCountersMatrix?.classList.add("view-hidden-state");
                listMeshSplitViewport?.classList.add("view-hidden-state");
                dashboardGridFeatureElement?.classList.add("view-hidden-state");
                
                sslMonitoringView?.classList.remove("view-hidden-state");
                renderSslMonitoringTabUI();
            }
            else if (rawButtonText.includes("analytics")) {
                currentActiveTabContext = "analytics";
                administrationDock?.classList.add("view-hidden-state");
                summaryCountersMatrix?.classList.add("view-hidden-state");
                listMeshSplitViewport?.classList.add("view-hidden-state");
                dashboardGridFeatureElement?.classList.add("view-hidden-state");
                
                analyticsView?.classList.remove("view-hidden-state"); // FIXED: Exclusively shows it here!
                renderAnalyticsTabUI();
            }
            else if (rawButtonText.includes("alerts")) {
                currentActiveTabContext = "alerts";
                administrationDock?.classList.add("view-hidden-state");
                summaryCountersMatrix?.classList.remove("view-hidden-state");
                listMeshSplitViewport?.classList.remove("view-hidden-state");
                dashboardGridFeatureElement?.classList.add("view-hidden-state");
            } 
            else {
                currentActiveTabContext = "other";
                administrationDock?.classList.add("view-hidden-state");
                summaryCountersMatrix?.classList.add("view-hidden-state");
                listMeshSplitViewport?.classList.add("view-hidden-state");
                dashboardGridFeatureElement?.classList.add("view-hidden-state");
            }
            renderDashboardUI();
        });
    });

   // Run initial rendering sequence
    initializeLogFeatureControlListeners(); 
    initializeSslFeatureControlListeners(); // INJECTED: Hooks up the bulk manual revalidation sync controls
    initializeDashboardPerformanceChart();
    renderDashboardUI();
});

// ─── UNIQUE EXCLUSIVE FEATURE: DYNAMIC LOAD VELOCITY DISTRIBUTION GRAPH ───
function initializeDashboardPerformanceChart() {
    const canvasElement = document.getElementById("dashboardPerformanceOverviewChart");
    if (!canvasElement) return;

    // Destroy old historical tracker object instances cleanly before rebuilding layout instances
    if (dashboardOverviewChartInstance) {
        dashboardOverviewChartInstance.destroy();
    }

    const ctx = canvasElement.getContext("2d");
    
    // Map live dataset arrays straight from your monitored targets lists to update the graphic
    const webLabels = monitoredTargets.map(t => t.name);
    const trafficLoadData = monitoredTargets.map(t => t.currentLiveKbps || Math.floor(Math.random() * 200) + 50);

    dashboardOverviewChartInstance = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: webLabels,
            datasets: [{
                label: 'Throughput Data Stream Index (kbps)',
                data: trafficLoadData,
                backgroundColor: [
                    'rgba(59, 130, 246, 0.4)',
                    'rgba(16, 185, 129, 0.4)',
                    'rgba(239, 68, 68, 0.4)',
                    'rgba(245, 158, 11, 0.4)',
                    'rgba(168, 50, 155, 0.4)',
                    'rgba(0, 102, 255, 0.4)',
                    'rgba(253, 126, 20, 0.4)'
                ],
                borderColor: [
                    '#3b82f6', '#10b981', '#ef4444', '#f59e0b', '#a8329b', '#0066ff', '#fd7e14'
                ],
                borderWidth: 1.5,
                borderRadius: 4,
                barThickness: 20
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: { display: false }
            },
            scales: {
                x: {
                    grid: { display: false },
                    ticks: { color: '#94a3b8', font: { size: 9, weight: '600' } }
                },
                y: {
                    beginAtZero: true,
                    grid: { color: 'rgba(30, 41, 59, 0.15)' },
                    ticks: { color: '#94a3b8', font: { size: 9 } }
                }
            }
        }
    });
}

// ─── HIGH-DENSITY DYNAMIC REAL RENDER ENGINE ───
function renderDashboardUI() {
    const listContainer = document.getElementById('compact-list-container');
    if (!listContainer) return;
    
    // Clear list completely before populating dynamic nodes
    listContainer.innerHTML = "";
    const currentEpochTime = new Date();
    
    // Sort items by priority anomaly scores to lift down nodes to visible view thresholds
    const sortedTargets = monitoredTargets
        .map((target, index) => ({ target, index }))
        .sort((a, b) => getAnomalyScore(a.target) - getAnomalyScore(b.target));

    // Metric counter totals sync logic
    let activeOnlineCount = monitoredTargets.filter(t => t.latencyHistory[t.latencyHistory.length - 1] > 0 && t.checkInterval !== "none").length;
    let outagesCount = monitoredTargets.filter(t => t.latencyHistory[t.latencyHistory.length - 1] === 0 && t.checkInterval !== "none").length;

    if (document.getElementById('total-sites')) document.getElementById('total-sites').innerText = monitoredTargets.length.toString().padStart(2, '0');
    if (document.getElementById('up-sites')) document.getElementById('up-sites').innerText = activeOnlineCount.toString().padStart(2, '0');
    if (document.getElementById('down-sites')) document.getElementById('down-sites').innerText = outagesCount.toString().padStart(2, '0');

    let dividerInserted = false;
    const hasAnomalies = sortedTargets.some(({ target }) => getAnomalyScore(target) < 5);

    // Draw Flagged Header Section when anomalies exist in current system state
    if (hasAnomalies && currentActiveTabContext !== "websites") {
        const anomalyHeader = document.createElement('div');
        anomalyHeader.style.cssText = `display: flex; align-items: center; gap: 0.75rem; margin: 0 0 0.25rem 0; padding: 0 0.25rem; font-size: 0.68rem; font-weight: 800; color: var(--pure-red); font-family: monospace; letter-spacing: 0.8px; user-select: none;`;
        anomalyHeader.innerHTML = `<div style="flex:1; height:1px; background: var(--pure-red); opacity:0.35;"></div><span style="background: rgba(220,53,69,0.08); padding: 0.2rem 0.6rem; border-radius: 3px; border: 1px solid rgba(220,53,69,0.2);">⚠️ FLAGGED TARGETS</span><div style="flex-grow:1;"></div>`;
        listContainer.appendChild(anomalyHeader);
    }

    // Dynamic filtering engine lookup map loops
    sortedTargets.forEach(({ target, index }) => {
        const latestLatency = target.latencyHistory[target.latencyHistory.length - 1];
        const isOnline = latestLatency > 0;
        const scoreValue = getAnomalyScore(target);

        // ROUTER SELECTION FILTER RULES:
        if (currentActiveTabContext === "alerts" && isOnline) {
            return; // Skip showing online items entirely inside the Alerts tab view
        }

        // 1. Create unified element container wrapper mapping
        const itemWrapperNode = document.createElement('div');
        itemWrapperNode.style.cssText = "display: flex; flex-direction: column; width: 100%; margin-bottom: 0.35rem;";

        const cardItemRow = document.createElement('div');
        cardItemRow.className = "compact-list-row-item";
        cardItemRow.style.cssText = `border-left: 4px solid ${isOnline ? "var(--pure-green)" : "var(--pure-red)"}; margin-bottom: 0;`;

        const remainingDays = Math.ceil((new Date(target.expDate) - new Date()) / (1000 * 60 * 60 * 24));
        cardItemRow.innerHTML = `
            <div class="row-left-content">
                <div class="row-node-name">${target.name} <span style="font-size:0.7rem; color:var(--pure-blue);">#${target.idToken}</span></div>
                <div class="row-node-url">${target.url}</div>
            </div>
            <div class="row-right-content">
                <span class="state-indicator ${isOnline ? 'ONLINE' : 'OFFLINE'}">${isOnline ? 'ONLINE' : 'OFFLINE'}</span>
                <span class="row-data-span">SSL: ${remainingDays <= 0 ? 'EXPIRED' : remainingDays + 'd'}</span>
                <span class="row-data-span">Diag: ${target.latestDiagnosticHttpStatusCode.split(' ')[0]}</span>
                <button class="row-action-delete-btn" data-idx="${index}">🗑️</button>
            </div>
        `;

        cardItemRow.querySelector('.row-action-delete-btn').addEventListener('click', (e) => {
            e.stopPropagation();
            if (monitoredTargets[index].timerId) clearInterval(monitoredTargets[index].timerId);
            const droppedAsset = monitoredTargets.splice(index, 1)[0];
            systemRecycleBin.push(droppedAsset);
            syncRecycleBinCountUI();
        });

       // ─── STABLE ACCORDION DISPATCH ENGINE (RETAINS OPEN STATE ON REFRESHTICKS) ───
        function buildInlineExtractionDetailsAccordion() {
            const validSamples = target.latencyHistory.filter(v => v > 0);
            const weightedAvg = validSamples.length > 0 ? Math.round(validSamples.reduce((a, b) => a + b, 0) / validSamples.length) : 0;
            const currentLastLatency = target.latencyHistory[target.latencyHistory.length - 1] || 0;
            const isNodeOnline = currentLastLatency > 0;
            
            const latencyJitterDelta = Math.abs(currentLastLatency - weightedAvg);
            const missingPackets = target.latencyHistory.filter(v => v === 0).length;
            const uptimeProbability = Math.round(((target.latencyHistory.length - missingPackets) / target.latencyHistory.length) * 100);
            
            let networkPerformanceRank = "⚡ EXCELLENT";
            let networkRankColor = "var(--pure-green)";
            if (!isNodeOnline) {
                networkPerformanceRank = "🚨 CRITICAL_DOWN";
                networkRankColor = "var(--pure-red)";
            } else if (currentLastLatency > globalSystemConfig.latencyThreshold) {
                networkPerformanceRank = "⚠️ BREACHED_DELAY";
                networkRankColor = "var(--pure-red)";
            } else if (currentLastLatency > globalSystemConfig.alertLevelTimeThreshold) {
                networkPerformanceRank = "⏳ SLUGGISH_NODE";
                networkRankColor = "var(--warning-yellow)";
            }

            const sslStatusText = remainingDays <= 0 ? "⚠️ EXPIRED RISK" : `${remainingDays} Days Left`;
            const sslStatusColor = remainingDays <= 15 ? "var(--pure-red)" : "var(--pure-green)";
            
            const operationalHealthPercentage = isNodeOnline ? Math.max(30, 100 - (target.failedChecksRun * 10)) : 0;
            const healthBarColor = operationalHealthPercentage > 85 ? "var(--pure-green)" : (operationalHealthPercentage > 50 ? "var(--warning-yellow)" : "var(--pure-red)");

            const inlineDetailsPanel = document.createElement('div');
            inlineDetailsPanel.className = "inline-extraction-details-panel";
            inlineDetailsPanel.style.cssText = `
                background: #0f172a; border: 1px dashed var(--border-clean); border-top: none;
                padding: 0.95rem; border-radius: 0 0 8px 8px; font-family: monospace; cursor: pointer;
                display: grid; grid-template-columns: 1fr 1.4fr; gap: 1.25rem; align-items: start;
                margin-bottom: 0.25rem;
            `;

            inlineDetailsPanel.innerHTML = `
                <div style="display: flex; flex-direction: column; gap: 0.45rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center;">
                        <span class="label" style="font-size: 0.62rem; font-weight: 800; color: var(--text-muted); text-transform: uppercase;">📊 LIVE_TREND_HISTORY:</span>
                        <button id="inline-copy-config-shortcut-btn" style="background: #1e293b; border: 1px solid var(--border-clean); color: #00f0ff; padding: 2px 6px; font-size: 0.62rem; border-radius: 4px; cursor: pointer; font-weight: bold; position: relative; z-index: 10;">📋 COPY_CONFIG</button>
                    </div>
                    <div style="width: 100%; height: 60px; background: #040811; border-radius: 4px; padding: 4px; border: 1px solid var(--border-clean); position: relative; overflow: hidden;">
                        <canvas id="inline-mini-spark-chart-${target.idToken}"></canvas>
                    </div>
                    <div style="font-size: 0.65rem; color: var(--text-muted); font-weight: bold; margin-top: 2px;">
                        <div style="display: flex; justify-content: space-between; margin-bottom: 2px;">
                            <span>CONNECTION_HEALTH:</span>
                            <span style="color: ${healthBarColor}">${operationalHealthPercentage}%</span>
                        </div>
                        <div style="width: 100%; height: 4px; background: #040811; border-radius: 2px; overflow: hidden; border: 1px solid var(--border-clean);">
                            <div style="width: ${operationalHealthPercentage}%; height: 100%; background: ${healthBarColor}; transition: width 0.4s ease;"></div>
                        </div>
                    </div>
                </div>
                <div class="log-terminal" style="background: #040811; border: 1px solid var(--border-clean); padding: 0.6rem; border-radius: 4px; display: flex; flex-direction: column; gap: 0.35rem; font-size: 0.72rem; max-height: none; overflow: hidden; color: #cbd5e1;">
                    <p style="color: var(--pure-blue); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin: 0;">> ENDPOINT_URL  : ${target.url}</p>
                    <p style="margin: 0;">> TELEMETRY_STAT : <span style="color: ${isNodeOnline ? 'var(--pure-green)' : 'var(--pure-red)'}; font-weight: bold;">${isNodeOnline ? 'ONLINE' : 'CRITICAL_CRASH'}</span></p>
                    <p style="margin: 0;">> PERFORMANCE_TIER: <span style="color: ${networkRankColor}; font-weight: bold;">${networkPerformanceRank}</span></p>
                    <p style="margin: 0;">> ROUTING_JITTER  : +/- ${latencyJitterDelta} ms variance matrix</p>
                    <p style="margin: 0;">> ACTIVE_LATENCY : ${currentLastLatency} ms (Avg: ${weightedAvg} ms)</p>
                    <p style="margin: 0;">> LIFE_PROBABILITY: <span style="color: var(--pure-green); font-weight: bold;">${uptimeProbability}% Stability</span> | Checks: ${target.totalChecksRun || 1}</p>
                    <p style="margin: 0;">> DIAG_HTTP_CODE : ${target.latestDiagnosticHttpStatusCode} | SSL: <span style="color: ${sslStatusColor}; font-weight: bold;">${sslStatusText}</span></p>
                    <div style="text-align: right; margin-top: 0.2rem; font-size: 0.62rem; color: var(--pure-blue); font-weight: bold; animation: textPulseGlow 1.5s infinite;">💡 CLICK CARD PANEL TO EXPAND FULL GRAPHS ➔</div>
                </div>
            `;

            itemWrapperNode.appendChild(inlineDetailsPanel);

            setTimeout(() => {
                buildNodeLineChart(`inline-mini-spark-chart-${target.idToken}`, target.latencyHistory, isNodeOnline, false, false, false);
            }, 15);

            inlineDetailsPanel.querySelector('#inline-copy-config-shortcut-btn')?.addEventListener('click', (e) => {
                e.stopPropagation();
                const rawTextToCopyString = `NODE_ID: #${target.idToken}\nNAME: ${target.name}\nURL: ${target.url}\nSTATUS: ${isNodeOnline ? 'ONLINE' : 'OFFLINE'}\nAVG_LATENCY: ${weightedAvg}ms\nPERF_RANK: ${networkPerformanceRank}`;
                navigator.clipboard.writeText(rawTextToCopyString).then(() => {
                    launchNotificationToast("Config metrics copied directly to terminal clipboard context.", "success");
                });
            });

            inlineDetailsPanel.addEventListener('click', (e) => {
                if (e.target.id === 'inline-copy-config-shortcut-btn') return;
                e.stopPropagation();
                if (typeof openDeepHistoryDiagnosticPanel === "function" && activeInspectedIndexForFilter !== null) {
                    openDeepHistoryDiagnosticPanel(activeInspectedIndexForFilter);
                }
            });
        }

        // Click interaction logic handles state setting/unsetting toggles
        cardItemRow.addEventListener('click', () => {
            activeInspectedIndexForFilter = index;
            const existingInlinePanel = itemWrapperNode.querySelector('.inline-extraction-details-panel');
            
            if (existingInlinePanel) {
                existingInlinePanel.remove();
                activeExpandedNodeIdToken = null; // Clear tracking reference if manually closed by user
                return;
            }

            document.querySelectorAll('.inline-extraction-details-panel').forEach(node => node.remove());
            
            activeExpandedNodeIdToken = target.idToken; // Lock token reference state
            buildInlineExtractionDetailsAccordion();
        });

        // RE-RENDER VERIFICATION CHECK: Automatically re-open the node if its token remains active globally
        if (activeExpandedNodeIdToken === target.idToken) {
            buildInlineExtractionDetailsAccordion();
        }

        // Pack the row element inside the wrapper box layout
        itemWrapperNode.insertBefore(cardItemRow, itemWrapperNode.firstChild);

        if (!dividerInserted && scoreValue === 5 && currentActiveTabContext !== "websites" && currentActiveTabContext !== "alerts") {
            dividerInserted = true;
            const divider = document.createElement('div');
            divider.style.cssText = `display: flex; align-items: center; gap: 0.75rem; margin: 0.25rem 0; padding: 0 0.25rem; font-size: 0.68rem; font-weight: 800; color: var(--pure-green); font-family: monospace; letter-spacing: 0.8px; user-select: none;`;
            divider.innerHTML = `<div style="flex:1; height:1px; background: var(--pure-green); opacity:0.35;"></div><span style="background: rgba(40,167,69,0.08); padding: 0.2rem 0.6rem; border-radius: 3px; border: 1px solid rgba(40,167,69,0.25);">✔ STABLE SYSTEM NODES</span><div style="flex-grow:1;"></div>`;
            listContainer.appendChild(divider);
        }

        listContainer.appendChild(itemWrapperNode);
    });

    let aggregateLatencyTotal = 0, monitoredProbesCount = 0;
    monitoredTargets.forEach(target => { const sample = target.latencyHistory[target.latencyHistory.length - 1]; if (target.checkInterval !== "none" && sample > 0) { aggregateLatencyTotal += sample; monitoredProbesCount++; } });
    if (document.getElementById('global-weighted-avg')) document.getElementById('global-weighted-avg').innerText = `${(monitoredProbesCount > 0 ? Math.round(aggregateLatencyTotal / monitoredProbesCount) : 0)} ms`;
    const totalActiveSitesCount = monitoredTargets.filter(t => t.checkInterval !== "none").length;
    
    // Automatically update the chart data points ONLY if the chart panel is actually present and visible
    if (currentActiveTabContext === "dashboard" && document.getElementById("dashboardPerformanceOverviewChart")) {
        const webLabels = monitoredTargets.map(t => t.name);
        const trafficLoadData = monitoredTargets.map(t => t.currentLiveKbps || 0);
        if (dashboardOverviewChartInstance) {
            dashboardOverviewChartInstance.data.labels = webLabels;
            dashboardOverviewChartInstance.data.datasets[0].data = trafficLoadData;
            dashboardOverviewChartInstance.update('none'); // Silent update without resetting layouts
        }
    }
}

function buildNodeLineChart(canvasId, historicalData, isOnline, isWarning, isDnsAlert, isWaitingAlert) {
    const canvasEl = document.getElementById(canvasId); if (!canvasEl) return;
    let strokeColor = isOnline ? '#10b981' : '#ef4444';
    new Chart(canvasEl.getContext('2d'), {
        type: 'line', data: { labels: ['', '', '', '', '', '', ''], datasets: [{ data: historicalData, borderColor: strokeColor, borderWidth: 2, pointRadius: 1.5, tension: 0.3, fill: false }] },
        options: { responsive: true, maintainAspectRatio: false, plugins: { legend: { display: false } }, scales: { x: { display: false }, y: { display: false, min: 0 } } }
    });
}

// Start system worker scheduling execution cycles
monitoredTargets.forEach((_, idx) => startTargetWorkerSchedule(idx));

// ─── DYNAMIC SECURITY HANDSHAKE & SSL MONITORING ENGINE CONTROLLER ───
function renderSslMonitoringTabUI() {
    const gridContainer = document.getElementById('ssl-grid-view-container');
    if (!gridContainer) return;

    if (monitoredTargets.length === 0) {
        gridContainer.innerHTML = `<div style="grid-column: 1/-1; color: var(--text-muted); text-align:center; padding: 3rem 1rem; font-family: monospace; font-size: 0.78rem;">> NO ACTIVE DOMAIN CHANNELS AVAILABLE IN TELEMETRY CONTEXT DATA ARRAYS.</div>`;
        return;
    }

    gridContainer.innerHTML = monitoredTargets.map(target => {
        // Calculate precise days left inside the expiration safety timeline
        const remainingDaysLeft = Math.ceil((new Date(target.expDate) - new Date()) / (1000 * 60 * 60 * 24));
        const normalizedCheckString = (target.name + " " + target.url).toLowerCase();
        const isInvalidOrFakeNode = !target.url.startsWith("http") || target.url.includes("fake") || target.url.includes("invalid") || target.url.includes("test.xyz");

        let statusTextBadge = "SECURE_HANDSHAKE";
        let statusAccentColor = "var(--pure-green)";
        let badgeBackgroundPillColor = "rgba(16, 185, 129, 0.08)";
        let simulatedIssuerAuthority = "Let's Encrypt E6 Operational Root";

        if (isInvalidOrFakeNode || remainingDaysLeft <= 0) {
            statusTextBadge = "CRITICAL_EXPIRED";
            statusAccentColor = "var(--pure-red)";
            badgeBackgroundPillColor = "rgba(239, 68, 68, 0.08)";
            simulatedIssuerAuthority = "UNKNOWN_REJECTED_SIGNATURE";
        } else if (remainingDaysLeft <= 30) {
            statusTextBadge = "WARNING_EXPIRING";
            statusAccentColor = "var(--warning-yellow)";
            badgeBackgroundPillColor = "rgba(245, 158, 11, 0.08)";
            simulatedIssuerAuthority = "Let's Encrypt Intermediate Staging Authority";
        }

        // Match corporate certificate authorities depending on the mapped platform targets
        if (!isInvalidOrFakeNode) {
            if (normalizedCheckString.includes("google")) simulatedIssuerAuthority = "Google Trust Services Global Root CA-1";
            if (normalizedCheckString.includes("facebook") || normalizedCheckString.includes("whatsapp")) simulatedIssuerAuthority = "DigiCert High Assurance EV Root CA";
            if (normalizedCheckString.includes("netflix")) simulatedIssuerAuthority = "DigiCert Baltimore CyberTrust Root CA";
        }

        return `
            <div style="background: #0b111e; border: 1px solid var(--border-clean); padding: 1.1rem; border-radius: 6px; display: flex; flex-direction: column; gap: 0.8rem; border-top: 4px solid ${statusAccentColor}; transition: transform 0.2s ease;">
                <div style="display: flex; justify-content: space-between; align-items: start; gap: 0.5rem;">
                    <div style="overflow: hidden;">
                        <strong style="color: #fff; font-size: 0.9rem; display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">${target.name}</strong>
                        <span style="font-family: monospace; font-size: 0.72rem; color: var(--text-muted); display: block; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; margin-top: 0.1rem;">${target.url}</span>
                    </div>
                    <span style="font-family: monospace; font-size: 0.6rem; font-weight: 900; background: ${badgeBackgroundPillColor}; color: ${statusAccentColor}; padding: 0.2rem 0.5rem; border-radius: 3px; border: 1px solid ${statusAccentColor}25; white-space: nowrap; letter-spacing: 0.2px;">
                        ${statusTextBadge}
                    </span>
                </div>

                <div style="background: #111827; border: 1px solid rgba(255,255,255,0.01); padding: 0.55rem 0.7rem; border-radius: 4px; display: flex; flex-direction: column; gap: 0.4rem; font-family: monospace; font-size: 0.7rem;">
                    <div style="display: flex; justify-content: space-between; align-items: center; gap: 0.5rem;"><span style="color: var(--text-muted);">ISSUER:</span><span style="color: #e2e8f0; font-weight: bold; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; text-align: right; max-width: 170px;">${simulatedIssuerAuthority}</span></div>
                    <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-muted);">CIPHER:</span><span style="color: #cbd5e1;">TLS_AES_256_GCM_SHA384</span></div>
                    <div style="display: flex; justify-content: space-between;"><span style="color: var(--text-muted);">KEY_SIZE:</span><span style="color: #cbd5e1;">RSA 2048-bit</span></div>
                </div>

                <div style="display: flex; justify-content: space-between; align-items: center; margin-top: 0.1rem; border-top: 1px solid rgba(255,255,255,0.03); padding-top: 0.5rem;">
                    <span style="color: var(--text-muted); font-size: 0.72rem; font-weight: 800; font-family: monospace;">⏳ TIME_UNTIL_LAPSE:</span>
                    <span style="font-size: 0.88rem; font-weight: 900; font-family: monospace; color: ${statusAccentColor}; letter-spacing: 0.2px;">
                        ${isInvalidOrFakeNode || remainingDaysLeft <= 0 ? '0 DAYS' : remainingDaysLeft + ' DAYS'}
                    </span>
                </div>
            </div>
        `;
    }).join('');
}

// ─── LOGIC ENGINE CONTROL HANDLER EVENT ATTACHMENTS ───
function initializeSslFeatureControlListeners() {
    const massSyncBtn = document.getElementById('trigger-bulk-ssl-sync-btn');
    massSyncBtn?.addEventListener('click', () => {
        massSyncBtn.disabled = true;
        massSyncBtn.innerText = "⚡ SYNCING_HANDSHAKES...";
        massSyncBtn.style.opacity = "0.6";

        monitoredTargets.forEach((_, idx) => {
            if (monitoredTargets[idx].checkInterval !== "none") {
                executeSingleProbeCheck(idx);
            }
        });

        setTimeout(() => {
            renderSslMonitoringTabUI();
            massSyncBtn.disabled = false;
            massSyncBtn.innerText = "⚡ REVALIDATE_ALL_CERTS";
            massSyncBtn.style.opacity = "1";
            launchNotificationToast("Global mesh security certificates revalidated successfully.", "success");
            triggerSpeechOutput("Security authentication checks executed completely across all encrypted paths.", null, true);
        }, 600);
    });
}
// ─── ADVANCED TELEMETRY ANALYTICS DISPATCHER ENGINE ───
function renderAnalyticsTabUI() {
    const totalChecksText = document.getElementById('analytics-total-checks');
    const failureRateText = document.getElementById('analytics-failure-rate');
    const leaderboardBox = document.getElementById('analytics-leaderboard-container');
    
    if (!leaderboardBox) return;

    // 1. Compute standalone session statistics entirely on demand
    let totalSystemRunsCalculated = 0;
    let totalSystemFailuresCalculated = 0;
    let nominalHits = 0;
    let anomalyHits = 0;
    let criticalHits = 0;

    // Look up state data dynamically out of live history arrays to map distributions accurately
    monitoredTargets.forEach(target => {
        if (target.latencyHistory) {
            target.latencyHistory.forEach(latency => {
                totalSystemRunsCalculated++;
                if (latency === 0) {
                    totalSystemFailuresCalculated++;
                    criticalHits++; // Pings with 0 latency are complete network drops
                } else if (latency > globalSystemConfig.latencyThreshold || latency >= globalSystemConfig.alertLevelTimeThreshold) {
                    anomalyHits++; // Latency thresholds breached
                } else {
                    nominalHits++; // Healthy check hits
                }
            });
        }
    });

    const runtimeFailureRatio = totalSystemRunsCalculated > 0 
        ? ((totalSystemFailuresCalculated / totalSystemRunsCalculated) * 100).toFixed(1) 
        : "0.0";

    if (totalChecksText) totalChecksText.innerText = totalSystemRunsCalculated;
    if (failureRateText) failureRateText.innerText = runtimeFailureRatio + "%";

    // 2. Generate Isolated Leaderboards utilizing real-time latency history ratios
    const sortedAvailabilityRankings = [...monitoredTargets].sort((x, y) => {
        const xRuns = x.latencyHistory ? x.latencyHistory.length : 1;
        const xDrops = x.latencyHistory ? x.latencyHistory.filter(l => l === 0).length : 0;
        const yRuns = y.latencyHistory ? y.latencyHistory.length : 1;
        const yDrops = y.latencyHistory ? y.latencyHistory.filter(l => l === 0).length : 0;
        
        return ((yRuns - yDrops) / yRuns) - ((xRuns - xDrops) / xRuns);
    });

    leaderboardBox.innerHTML = sortedAvailabilityRankings.map((target, rankingIndex) => {
        const historyLength = target.latencyHistory ? target.latencyHistory.length : 1;
        const deadHeartbeats = target.latencyHistory ? target.latencyHistory.filter(l => l === 0).length : 0;
        const calculatedUptimeScore = (((historyLength - deadHeartbeats) / historyLength) * 100).toFixed(0);
        
        let trackColorAccent = "var(--pure-green)";
        if (calculatedUptimeScore < 98) trackColorAccent = "var(--warning-yellow)";
        if (calculatedUptimeScore < 90) trackColorAccent = "var(--pure-red)";

        return `
            <div style="display: flex; justify-content: space-between; align-items: center; background: #111827; padding: 0.5rem 0.8rem; border-radius: 4px; border: 1px solid var(--border-clean); font-family: monospace; font-size: 0.74rem;">
                <div style="display: flex; gap: 0.6rem; align-items: center; overflow: hidden;">
                    <span style="color: var(--pure-blue); font-weight: 900;">#0${rankingIndex + 1}</span>
                    <strong style="color: #fff; text-overflow: ellipsis; overflow: hidden; white-space: nowrap; max-width: 140px;">${target.name.toUpperCase()}</strong>
                </div>
                <div style="display: flex; align-items: center; gap: 0.8rem;">
                    <span style="color: var(--text-muted); font-size: 0.68rem;">SAMPLES: ${historyLength}</span>
                    <span style="color: ${trackColorAccent}; font-weight: 900; background: ${trackColorAccent}12; padding: 0.1rem 0.4rem; border-radius: 3px; border: 1px solid ${trackColorAccent}20;">
                        ${calculatedUptimeScore}% AVAILABLE
                    </span>
                </div>
            </div>
        `;
    }).join('');

    // 3. Forward metrics to the graph canvas compiler component
    initializeAnalyticsDistributionPieChart(nominalHits, anomalyHits, criticalHits);
}
// ─── INITIALIZE OR DESTROY PIE CHART CANVAS INSTANCES ───
function initializeAnalyticsDistributionPieChart(nominal, anomaly, critical) {
    const chartElement = document.getElementById('analyticsDistributionPieChart');
    if (!chartElement) return;

    const valuesArray = (nominal === 0 && anomaly === 0 && critical === 0) ? [1, 0, 0] : [nominal, anomaly, critical];

    // Destroy the canvas context structure to force dimension updates when entering hidden containers
    if (globalAnalyticsDistributionChartInstance) {
        globalAnalyticsDistributionChartInstance.destroy();
        globalAnalyticsDistributionChartInstance = null;
    }

    const contextRef = chartElement.getContext('2d');
    globalAnalyticsDistributionChartInstance = new Chart(contextRef, {
        type: 'doughnut',
        data: {
            labels: ['NOMINAL', 'DEGRADED', 'CRITICAL'],
            datasets: [{
                data: valuesArray,
                backgroundColor: ['#10b981', '#f59e0b', '#ef4444'],
                borderColor: '#111827',
                borderWidth: 2,
                hoverOffset: 4
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            animation: { duration: 400 },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#94a3b8',
                        font: { family: 'monospace', size: 10, weight: 'bold' }
                    }
                }
            },
            cutout: '70%'
        }
    });
}

// ─── OPERATIONAL TELEMETRY CHINNU AI ASSISTANT CLIENT ENGINE ───
document.addEventListener("DOMContentLoaded", () => {
    // FIXED SELECTORS: Added fallbacks to ensure it captures whatever ID/Class you used in index.html (pandu or chinnu)
    const triggerBtn = document.getElementById("chinnu-trigger-floating-btn") || document.getElementById("pandu-trigger-floating-btn");
    const drawerPanel = document.getElementById("chinnu-chat-drawer-panel") || document.getElementById("pandu-chat-drawer-panel");
    const closeDrawerBtn = document.getElementById("close-chinnu-drawer-btn") || document.getElementById("close-pandu-drawer-btn");
    const sendMessageBtn = document.getElementById("chinnu-send-message-btn") || document.getElementById("pandu-send-message-btn");
    const userInputBox = document.getElementById("chinnu-user-input-box") || document.getElementById("pandu-user-input-box");
    const chatScreenLogs = document.getElementById("chinnu-chat-screen-logs") || document.getElementById("pandu-chat-screen-logs");
    
    // Captures both chinnu and pandu prompt chips from index.html so clicks work instantly!
    const suggestChips = document.querySelectorAll(".chinnu-prompt-suggest-chip, .pandu-prompt-suggest-chip");

    // ⚠️ PLEASE INJECT YOUR API KEY HERE FOR LIVE REMOTE REST HANDSHAKES
    const GEMINI_API_KEY_TOKEN = "AIzaSyYourActualAPIKeyGoesHere";

    // Toggle Chat Drawer Window Open/Closed Context
    triggerBtn?.addEventListener("click", () => {
        if (!drawerPanel) return;
        const isHidden = drawerPanel.style.display === "none" || drawerPanel.style.display === "";
        drawerPanel.style.display = isHidden ? "flex" : "none";
    });

    closeDrawerBtn?.addEventListener("click", () => { 
        if (drawerPanel) drawerPanel.style.display = "none"; 
    });

    // Wire up prompt chips click listeners directly to execute instantly
    suggestChips.forEach(chip => {
        chip.addEventListener("click", () => {
            if (userInputBox) {
                userInputBox.value = chip.textContent;
                processChinnuQueryCycle();
            }
        });
    });

    sendMessageBtn?.addEventListener("click", processChinnuQueryCycle);
    userInputBox?.addEventListener("keypress", (e) => { if (e.key === "Enter") processChinnuQueryCycle(); });

    async function processChinnuQueryCycle() {
        const userPromptQueryText = userInputBox.value.trim();
        if (!userPromptQueryText) return;

        // Render user message box immediately
        appendChatBubbleMarkup(userPromptQueryText, "user");
        userInputBox.value = "";

        // Render unique tracked processing loader element block
        const loaderPillId = "loader-" + Date.now();
        appendChatBubbleMarkup("<span style='color:#00f0ff; font-weight:bold;'>🔄 Chinnu is reading operational matrix database arrays...</span>", "ai", loaderPillId);

        // Extract current live runtime state right out of memory variables!
        const liveTelemetryContextSnapshot = {
            systemTime: new Date().toLocaleString(),
            globalCounters: {
                totalMonitoredSites: monitoredTargets.length,
                onlineNodesCount: monitoredTargets.filter(t => t.latencyHistory[t.latencyHistory.length - 1] > 0 && t.checkInterval !== "none").length,
                outagesDetectedCount: monitoredTargets.filter(t => t.latencyHistory[t.latencyHistory.length - 1] === 0 && t.checkInterval !== "none").length
            },
            activeWebsitesDataset: monitoredTargets.map(site => {
                const recentLatencies = site.latencyHistory || [];
                const currentLatencyValue = recentLatencies[recentLatencies.length - 1];
                return {
                    identifierName: site.name,
                    endpointLocationUrl: site.url,
                    currentLiveStatus: (currentLatencyValue > 0) ? "ONLINE" : "OFFLINE/DOWN",
                    lastLatencyPing: currentLatencyValue + " ms",
                    averageLatencyMetrics: Math.round(recentLatencies.reduce((a,b)=>a+b, 0) / (recentLatencies.length || 1)) + " ms",
                    totalAlertsRegistered: site.sessionAlertsCount || 0,
                    sslExpirationLimit: site.expDate,
                    httpStatusCode: site.latestDiagnosticHttpStatusCode || "200 OK"
                };
            }),
            recentSystemEventLogsTail: systemOperationalLogsMemory.slice(0, 10).map(log => `[${log.time}] (${log.severity.toUpperCase()}) ${log.name || 'CORE'}: ${log.text}`)
        };

        // 🛠️ LIVE INTERCEPT ENGINE: If no real API key is written yet, run direct array parsing natively instead of failing!
        if (GEMINI_API_KEY_TOKEN.includes("YourActualAPIKey") || !GEMINI_API_KEY_TOKEN) {
            document.getElementById(loaderPillId)?.remove();
            
            const total = liveTelemetryContextSnapshot.globalCounters.totalMonitoredSites;
            const online = liveTelemetryContextSnapshot.globalCounters.onlineNodesCount;
            const offline = liveTelemetryContextSnapshot.globalCounters.outagesDetectedCount;
            const normalizedQueryText = userPromptQueryText.toLowerCase();
            
            let localReplyMarkup = `🤖 <strong>Chinnu Real-Time Engine Active:</strong><br><br>`;
            
            if (normalizedQueryText.includes("down") || normalizedQueryText.includes("offline") || normalizedQueryText.includes("outage")) {
                const targetsDown = liveTelemetryContextSnapshot.activeWebsitesDataset.filter(w => w.currentLiveStatus.includes("OFFLINE"));
                if (targetsDown.length === 0) {
                    localReplyMarkup += "🟢 Operational health checks nominal! **0 outages** reported across your monitored fleet right now.";
                } else {
                    localReplyMarkup += `🚨 <strong>Active System Outages Detected (${targetsDown.length}):</strong><br>`;
                    targetsDown.forEach(site => {
                        localReplyMarkup += `• <strong>${site.identifierName}</strong> (<a href="${site.endpointLocationUrl}" target="_blank" style="color:#3b82f6;">link</a>) is currently down. Latency: <code>${site.lastLatencyPing}</code> (Code: ${site.httpStatusCode})<br>`;
                    });
                }
            } 
            else if (normalizedQueryText.includes("summary") || normalizedQueryText.includes("report") || normalizedQueryText.includes("performance") || normalizedQueryText.includes("status")) {
                localReplyMarkup += `📊 <strong>Live Telemetry Matrix Checklist Summary:</strong><br>`;
                localReplyMarkup += `• Total Sites Registered: <strong>${total}</strong><br>`;
                localReplyMarkup += `• Active Nodes Online: <span style="color:#10b981; font-weight:bold;">${online}</span><br>`;
                localReplyMarkup += `• Critical Disconnections: <span style="color:#ef4444; font-weight:bold;">${offline}</span><br><br>`;
                
                localReplyMarkup += `<strong>Target Fleet Processing Speeds:</strong><br>`;
                liveTelemetryContextSnapshot.activeWebsitesDataset.forEach(site => {
                    const statusColor = site.currentLiveStatus === "ONLINE" ? "#10b981" : "#ef4444";
                    localReplyMarkup += `• ${site.identifierName}: <strong style="color:${statusColor};">${site.lastLatencyPing}</strong> (Avg: ${site.averageLatencyMetrics} | Alerts: ${site.totalAlertsRegistered})<br>`;
                });
            } 
            else {
                localReplyMarkup += `I am reading your workspace memory variables natively! I see <strong>${total} targets</strong> total (${online} running online, ${offline} offline).<br><br>👉 Click one of the prompt suggestion cards above, or try typing: <em>"Which sites are down right now?"</em> to get a real live analysis text report instantly.`;
            }
            
            appendChatBubbleMarkup(localReplyMarkup, "ai");
            return; 
        }

        try {
            const apiRequestEndpointUrl = `https://generativelanguage.googleapis.com/v1beta/models/gemini-1.5-flash:generateContent?key=${GEMINI_API_KEY_TOKEN}`;
            const outboundPayloadData = {
                contents: [{
                    parts: [{
                        text: `You are Chinnu Monitor Assistant, the native embedded system AI helper for this network monitoring workspace dashboard.
You are given a direct real-time snapshot of the application's global runtime metrics dataset arrays down below.
Read the data carefully to answer the user's inquiry accurately. Be concise, tech-focused, and output using clean formatting.
--- LIVE SYSTEM MEMORY MATRIX SNAPSHOT ---
${JSON.stringify(liveTelemetryContextSnapshot, null, 2)}
--- END OF SNAPSHOT ---

User Inquiry: "${userPromptQueryText}"`
                    }]
                }]
            };
            const response = await fetch(apiRequestEndpointUrl, {
                method: "POST",
                headers: { "Content-Type": "application/json" },
                body: JSON.stringify(outboundPayloadData)
            });

            if (!response.ok) throw new Error(`HTTP network response fault code: ${response.status}`);

            const structuredJsonResponse = await response.json();
            document.getElementById(loaderPillId)?.remove();

            let cleanAiReplyText = structuredJsonResponse?.candidates?.[0]?.content?.parts?.[0]?.text;
            if (!cleanAiReplyText) {
                cleanAiReplyText = "⚠️ Warning: Received an empty content structural frame layout response from the AI processing engine.";
            }

            cleanAiReplyText = cleanAiReplyText
                .replace(/\n/g, "<br>")
                .replace(/\*\*(.*?)\*\"/g, "<strong>$1</strong>")
                .replace(/^\*\s(.*)/gm, "• $1");
            appendChatBubbleMarkup(cleanAiReplyText, "ai");

        } catch (errorFaultException) {
            console.error("Chinnu AI Assistant Integration Fault Exception:", errorFaultException);
            document.getElementById(loaderPillId)?.remove();
            appendChatBubbleMarkup("🛑 <strong>System Intercept Fault:</strong> Failed to get an answer. Please check your internet connectivity loops or confirm that your Gemini API key token is written correctly.", "ai");
        }
    }

    function appendChatBubbleMarkup(message, senderType, trackingId = null) {
        const bubbleWrapperNode = document.createElement("div");
        if (trackingId) bubbleWrapperNode.id = trackingId;
        
        bubbleWrapperNode.style.maxWidth = "88%";
        bubbleWrapperNode.style.padding = "0.65rem 0.85rem";
        bubbleWrapperNode.style.borderRadius = "8px";
        bubbleWrapperNode.style.fontSize = "0.76rem";
        bubbleWrapperNode.style.lineHeight = "1.45";
        bubbleWrapperNode.style.wordBreak = "break-word";
        bubbleWrapperNode.style.margin = "0.2rem 0";

        if (senderType === "user") {
            bubbleWrapperNode.style.background = "#1e293b";
            bubbleWrapperNode.style.color = "#ffffff";
            bubbleWrapperNode.style.alignSelf = "flex-end";
            bubbleWrapperNode.style.borderBottomRightRadius = "2px";
        } else {
            bubbleWrapperNode.style.background = "#111827";
            bubbleWrapperNode.style.color = "#cbd5e1";
            bubbleWrapperNode.style.alignSelf = "flex-start";
            bubbleWrapperNode.style.borderBottomLeftRadius = "2px";
            bubbleWrapperNode.style.borderLeft = "2px solid #00f0ff";
        }

        bubbleWrapperNode.innerHTML = message;
        chatScreenLogs?.appendChild(bubbleWrapperNode);
        if (chatScreenLogs) {
            chatScreenLogs.scrollTop = chatScreenLogs.scrollHeight;
        }
    }
});
// ─── TERMINAL SESSION CLOSURE INTERCEPT PIPELINE (LOGOUT ACTION MANAGER) ───
document.getElementById('system-logout-action-btn')?.addEventListener('click', () => {
    const authOverlayGate = document.getElementById('system-auth-overlay');
    if (authOverlayGate) {
        // Clear runtime state tracking configs safely
        systemWorkspaceIsUnlocked = false; 
        
        // Restore login form visibility structure cleanly
        authOverlayGate.style.display = 'grid';
        toggleBackgroundScroll(true);
        
        // Reset input fields cleanly
        if (document.getElementById('login-email')) document.getElementById('login-email').value = "";
        if (document.getElementById('login-pass')) document.getElementById('login-pass').value = "";
        if (document.getElementById('auth-captcha-checkbox')) document.getElementById('auth-captcha-checkbox').checked = false;
        
        // RE-IGNITE GLOBAL WEB GL RE-RENDER ENGINE HOOK: Restarts animation updates loop safely
        if (typeof drawGlobalMesh === "function") {
            requestAnimationFrame(drawGlobalMesh);
        } else {
            // Fallback safety to force reload matrix variables if enclosed inside anonymous closures
            const canvasElementCheck = document.getElementById('auth-racing-dashboard-cluster');
            if (canvasElementCheck && canvasElementCheck.style.display !== 'none') {
                 // Triggers canvas screen refresh cascade
                 location.reload();
                 return;
            }
        }
        
        launchNotificationToast("Operator context terminated. Returning to security gateway.", "warning");
        triggerSpeechOutput("System session signed out completely.", null, true);
    }
});