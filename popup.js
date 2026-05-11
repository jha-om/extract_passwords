"use strict"

const PBKDF2_ITERATIONS = 100_000;
const DERIVE_SALT = "extract_password_salt_v1";
const VERIFY_TOKEN = "extractpass_verify_ok";

const TWO_PART_TLDS = new Set([
    'co.uk', 'co.in', 'co.jp', 'co.nz', 'co.za', 'co.kr', 'co.id',
    'com.au', 'com.br', 'com.mx', 'com.sg', 'com.ph', 'com.ar',
    'org.uk', 'me.uk', 'net.au', 'net.nz'
]);

async function deriveKey(masterPassword) {
    const enc = new TextEncoder();
    const keyMaterial = await crypto.subtle.importKey('raw', enc.encode(masterPassword), 'PBKDF2', false, ['deriveKey']);

    return crypto.subtle.deriveKey(
        {
            name: "PBKDF2",
            salt: enc.encode(DERIVE_SALT),
            iterations: PBKDF2_ITERATIONS,
            hash: "SHA-256"
        },
        keyMaterial,
        {
            name: "AES-GCM",
            length: 256,
        },
        false,
        ['encrypt', 'decrypt']
    );
}

async function encryptData(value, masterPassword) {
    const key = await deriveKey(masterPassword);
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const encrypted = await crypto.subtle.encrypt(
        {
            name: "AES-GCM",
            iv,
        },
        key,
        new TextEncoder().encode(JSON.stringify(value))
    );
    return {
        iv: Array.from(iv),
        data: Array.from(new Uint8Array(encrypted))
    }
};

async function decryptData(encryptedObj, masterPassword) {
    const key = await deriveKey(masterPassword);
    const decrypted = await crypto.subtle.decrypt(
        {
            name: "AES-GCM",
            iv: new Uint8Array(encryptedObj.iv),
        },
        key,
        new Uint8Array(encryptedObj.data)
    );

    return JSON.parse(new TextDecoder().decode(decrypted));
}

async function setupMasterPassword(masterPassword) {
    const encrypted = await encryptData(VERIFY_TOKEN, masterPassword);
    await chrome.storage.local.set({
        masterVerify: encrypted,
        isSetup: true,
    });
}

async function verifyMasterPassword(masterPassword) {
    const { masterVerify } = await chrome.storage.local.get('masterVerify');
    if (!masterVerify) {
        return false;
    }
    try {
        const result = await decryptData(masterVerify, masterPassword);
        return result === VERIFY_TOKEN;
    } catch {
        return false;
    }
}

// parsing csv file for any additional character("/,...), is it included in the password or not;
function parseCsvLine(line) {
    const fields = [];
    let current = '';
    let inQuotes = false;

    for (let i = 0; i < line.length; i++) {
        const ch = line[i];
        const next = line[i + 1];

        if (ch === '"' && inQuotes && next === '"') {
            current += '"';
            i++;
        } else if (ch === '"') {
            inQuotes = !inQuotes;
        } else if (ch === ',' && !inQuotes) {
            fields.push(current.trim());
            current = '';
        } else {
            current += ch;
        }
    }

    fields.push(current.trim());
    return fields;
}

// getting clean domain from URL, handling regular and two-part TLDs;
function getWebsiteName(name, url) {
    if (name && name.trim() !== '') {
        return name.trim();
    }
    try {
        const { hostname } = new URL(url);
        const stripped = hostname.replace(/^www\./, '');
        const parts = stripped.split('.');

        if (parts.length >= 3 && TWO_PART_TLDS.has(parts.slice(-2).join('.'))) {
            return parts.slice(-3).join('.');
        }
        return parts.slice(-2).join('.');
    } catch {
        return url
    }
}

function findColIndex(headers, candidates) {
    for (const c of candidates) {
        const idx = headers.indexOf(c);
        if (idx !== -1) return idx;
    }
    return -1;
}

// parsing all browsers csv exports;
function parsePasswordCsv(csvText) {
    const lines = csvText.trim().split(/\r?\n/);
    if (lines.length < 2) {
        return [];
    }
    const headers = parseCsvLine(lines[0]).map(h => h.toLowerCase().replace(/[^a-z]/g, ''));
    const col = {
        name: findColIndex(headers, ['name', 'origin', 'title']),
        url: findColIndex(headers, ['url', 'origin', 'httpara']),
        username: findColIndex(headers, ['username', 'login', 'email', 'user', 'loginname']),
        password: findColIndex(headers, ['password', 'pass', 'pwd']),
    };

    if (col.password === -1 || col.username === -1) return [];

    const results = [];
    for (let i = 1; i < lines.length; i++) {
        const line = lines[i].trim();
        if (!line) continue;

        const fields = parseCsvLine(line);
        const rawName = col.name !== -1 ? fields[col.name] || '' : '';
        const rawUrl = col.url !== -1 ? fields[col.url] || '' : '';
        const username = col.username !== -1 ? fields[col.username] || '' : '';
        const password = col.password !== -1 ? fields[col.password] || '' : '';

        if (username.toLowerCase() === 'username' || password.toLowerCase() === 'password') continue;

        const website = getWebsiteName(rawName, rawUrl);
        if (website || username) results.push({ website, username, password });
    }
    return results;
}

// storing in the local
function makeDedupeKey(website, username) {
    return `${website.toLowerCase().trim()}||${username.toLowerCase().trim()}`;
}

async function getStoredPasswords(masterPassword) {
    const { passwordEncrypted } = await chrome.storage.local.get('passwordEncrypted');
    if (!passwordEncrypted) return [];
    return decryptData(passwordEncrypted, masterPassword);
}

// merging new passwords into storage;
// - same website + username -> different password => update
// - new website + username => add
async function mergeAndSave(newPasswords, masterPassword) {
    const existing = await getStoredPasswords(masterPassword);

    const map = {};
    for (const entry of existing) {
        map[makeDedupeKey(entry.website, entry.username)] = entry;
    }

    let added = 0, updated = 0;
    for (const entry of newPasswords) {
        const key = makeDedupeKey(entry.website, entry.username);
        if (map[key]) {
            if (map[key].password !== entry.password) {
                map[key].password = entry.password;
                updated++;
            }
        } else {
            map[key] = entry;
            added++;
        }
    }

    const merged = Object.values(map).sort((a, b) =>
        a.website.toLowerCase().localeCompare(b.website.toLowerCase())
    );

    const encrypted = await encryptData(merged, masterPassword);
    await chrome.storage.local.set({
        passwordEncrypted: encrypted,
        lastUpdated: new Date().toISOString()
    });

    return {
        merged,
        added,
        updated,
    }
}

async function clearAllData() {
    await chrome.storage.local.clear();
}

// export csv
function sanitizeFileName(name) {
    return name.trim().replace(/[\/\\:*?"<>|]/g, '_');
}

function exportToExcel(passwords, fileName) {
    const safeFileName = sanitizeFileName(fileName) || "saved_passwords";

    const rows = [
        ['Website/App', 'Username/Email', 'Password'],
        ...passwords.map(p => [p.website, p.username, p.password]),
    ];

    const workbook = XLSX.utils.book_new();
    const worksheet = XLSX.utils.aoa_to_sheet(rows);

    worksheet['!cols'] = [{ wch: 32 }, { wch: 30 }, { wch: 24 }];
    worksheet['!freeze'] = { xSplit: 0, ySplit: 1 };

    ['A1', 'B1', 'C1'].forEach(ref => {
        if (!worksheet[ref]) return;
        worksheet[ref].s = {
            font: { bold: true, color: { rgb: '000000' } },
            fill: { fgColor: { rgb: '4ade80' } },
            alignment: { horizontal: 'center' },
        };
    });

    XLSX.utils.book_append_sheet(workbook, worksheet, 'Passwords');
    XLSX.writeFile(workbook, `${safeFileName}.xlsx`);
}

// ui
let toastTimer = null;

function showToast(message, type = 'success', duration = 3000) {
    const toast = document.getElementById('toast');
    toast.textContent = message;
    toast.className = `show ${type}`;
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => { toast.className = ''; }, duration);
}

function showError(msg) { showToast(msg, 'error', 4000); }
function showSuccess(msg) { showToast(msg, 'success', 3000); }

function setFieldError(id, msg) {
    const el = document.getElementById(id);
    if (el) el.textContent = msg;
}
function clearFieldError(id) {
    const el = document.getElementById(id);
    if (el) el.textContent = '';
}

function showScreen(name) {
    document.querySelectorAll('.screen').forEach(s => s.classList.remove('active'));
    document.getElementById(`screen-${name}`).classList.add('active');
}

function updateStats(count, isoTimestamp) {
    document.getElementById('stats-count').textContent = count;
    const el = document.getElementById('stats-updated');
    if (isoTimestamp) {
        const d = new Date(isoTimestamp);
        el.textContent = `Updated ${d.toLocaleDateString()} ${d.toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' })}`;
    } else {
        el.textContent = 'Never imported';
    }
}

function evaluateStrength(password) {
    const fill = document.getElementById('strength-fill');
    if (!fill) return;
    let score = 0;
    if (password.length >= 8) score++;
    if (password.length >= 12) score++;
    if (/[A-Z]/.test(password) && /[a-z]/.test(password)) score++;
    if (/[0-9]/.test(password)) score++;
    if (/[^A-Za-z0-9]/.test(password)) score++;
    const levels = [
        { pct: '0%', color: 'transparent' },
        { pct: '25%', color: '#f87171' },
        { pct: '50%', color: '#fb923c' },
        { pct: '75%', color: '#facc15' },
        { pct: '90%', color: '#4ade80' },
        { pct: '100%', color: '#4ade80' },
    ];
    const level = levels[Math.min(score, levels.length - 1)];
    fill.style.width = level.pct;
    fill.style.background = level.color;
}

let masterPassword = null;

// password visibility toglge
document.querySelectorAll('.eye-btn').forEach(btn => {
    btn.addEventListener('click', () => {
        const input = document.getElementById(btn.dataset.target);
        input.type = input.type === 'password' ? 'text' : 'password';
        btn.textContent = input.type === 'password' ? '👁' : '🙈';
    })
});

// checking password strenght
document.getElementById('setup-pw').addEventListener('input', e => evaluateStrength(e.target.value));

// key-shortcuts
document.getElementById('unlock-pw').addEventListener('keydown', e => {
    if (e.key === 'Enter') {
        document.getElementById('btn-unlock').click();
    };
    document.getElementById('setup-confirm').addEventListener('keydown', e => {
        if (e.key === 'Enter') {
            document.getElementById('btn-setup').click();
        };
    })
});

document.getElementById('btn-setup').addEventListener('click', async () => {
    clearFieldError('setup-error');
    const pw = document.getElementById('setup-pw').value;
    const confirm = document.getElementById('setup-confirm').value;

    if (!pw) {
        return setFieldError('setup-error', 'Password cannot be empty.')
    };
    if (pw.length < 8) {
        return setFieldError('setup-error', 'Use at least 8 characters.')
    };
    if (pw !== confirm) {
        return setFieldError('setup-error', 'Passwords do not match.')
    };

    const btn = document.getElementById('btn-setup');
    btn.disabled = true;
    btn.textContent = 'Setting up...';

    try {
        await setupMasterPassword(pw);
        masterPassword = pw;
        await loadMainScreen();
        showScreen('main');
        showSuccess('Master password set. You\'re all set!');
    } catch (err) {
        setFieldError('setup-error', 'Setup failed: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Set Master Password →';
    }
})

document.getElementById('btn-unlock').addEventListener('click', async () => {
    clearFieldError('unlock-error');
    const pw = document.getElementById('unlock-pw').value;
    if (!pw) {
        return setFieldError('unlock-error', 'Enter your master password.')
    };

    const btn = document.getElementById('btn-unlock');
    btn.disabled = true;
    btn.textContent = 'Verifying…';
    try {
        const valid = await verifyMasterPassword(pw);
        if (!valid) {
            return setFieldError('unlock-error', 'Wrong password. Try again.')
        };
        masterPassword = pw;
        await loadMainScreen();
        showScreen('main');
    } catch (err) {
        setFieldError('unlock-error', 'Error: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = 'Unlock →';
    }
});

document.getElementById('btn-reset').addEventListener('click', async () => {
    if (!confirm('⚠️ This deletes ALL stored passwords and your master password.\n\nAre you sure?')) return;
    await clearAllData();
    masterPassword = null;
    showScreen('setup');
    showSuccess('All data cleared.');
});

document.getElementById('csv-file').addEventListener('change', async (e) => {
    const file = e.target.files[0];
    if (!file || !masterPassword) return;

    document.querySelector('.file-drop-text').innerHTML = `<strong>${file.name}</strong> — importing…`;

    try {
        const text = await file.text();
        const newPasswords = parsePasswordCsv(text);

        if (newPasswords.length === 0) {
            showError('Could not parse CSV. Is this a browser password export?');
            resetFileDropLabel(); return;
        }

        const { merged, added, updated } = await mergeAndSave(newPasswords, masterPassword);
        const { lastUpdated } = await chrome.storage.local.get('lastUpdated');
        updateStats(merged.length, lastUpdated);
        document.getElementById('btn-export').disabled = false;
        document.querySelector('.file-drop-text').innerHTML = `<strong>${file.name}</strong>`;
        showSuccess(`Done! +${added} new, ${updated} updated. ${merged.length} total.`);
    } catch (err) {
        showError('Import failed: ' + err.message);
        resetFileDropLabel();
    }
    e.target.value = ''; // allowing re-importing same file
});

function resetFileDropLabel() {
    document.querySelector('.file-drop-text').innerHTML =
        'Click to select CSV &nbsp;·&nbsp; <strong>passwords.csv</strong>';
}

document.getElementById('btn-export').addEventListener('click', async () => {
    if (!masterPassword) return;
    const fileName = document.getElementById('file-name').value.trim() || 'saved_passwords';
    const btn = document.getElementById('btn-export');

    btn.disabled = true;
    btn.textContent = '⏳ Exporting…';
    try {
        const passwords = await getStoredPasswords(masterPassword);
        if (passwords.length === 0) {
            return showError('No passwords stored. Import a CSV first.')
        };
        exportToExcel(passwords, fileName);
        showSuccess(`Exported ${passwords.length} passwords → ${sanitizeFileName(fileName)}.xlsx`);
    } catch (err) {
        showError('Export failed: ' + err.message);
    } finally {
        btn.disabled = false;
        btn.textContent = '↓ Export to Excel';
    }
});

document.getElementById('btn-clear').addEventListener('click', async () => {
    if (!confirm('Delete all stored passwords? Your master password is kept.\n\nContinue?')) return;
    await chrome.storage.local.remove(['passwordEncrypted', 'lastUpdated']);
    updateStats(0, null);
    document.getElementById('btn-export').disabled = true;
    showSuccess('All passwords cleared.');
});

async function loadMainScreen() {
    try {
        const passwords = await getStoredPasswords(masterPassword);
        const { lastUpdated } = await chrome.storage.local.get('lastUpdated');
        updateStats(passwords.length, lastUpdated || null);
        document.getElementById('btn-export').disabled = passwords.length === 0;
    } catch {
        updateStats(0, null);
    }
}

async function init() {
    const { isSetup } = await chrome.storage.local.get('isSetup');
    showScreen(isSetup ? 'unlock' : 'setup');
    setTimeout(() => {
        const field = isSetup
            ? document.getElementById('unlock-pw')
            : document.getElementById('setup-pw');
        field?.focus();
    }, 50);
}

init();
