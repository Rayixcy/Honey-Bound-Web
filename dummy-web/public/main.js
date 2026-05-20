'use strict';

/**
 * Shared UI - Show Alerts
 */
window.showAlert = function (text, type) {
    const el = document.getElementById('alert');
    if (!el) return;
    el.innerHTML = (type === 'error' ? '⚠️ ' : '✓ ') + text;
    el.className = 'alert ' + type;
    el.style.display = 'flex';
};

/**
 * Handle Login — with proper delay before OTP redirect
 */
window.doLogin = async function () {
    const u = document.getElementById('username').value.trim();
    const p = document.getElementById('password').value;
    const btn = document.getElementById('loginBtn');
    
    if (!u || !p) {
        return showAlert('Please fill in all fields.', 'error');
    }

    btn.classList.add('loading');
    btn.textContent = 'Signing in…';

    try {
        const r = await fetch('/api/login', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ username: u, password: p })
        });
        
        if (!r.ok) throw new Error('Server error ' + r.status);
        
        const d = await r.json();
        
        if (d.success) {
            showAlert('Password verified! Redirecting to OTP…', 'success');
            
            // ✅ FIX: Add 800ms delay so user sees the success message
            // and OTP page loads properly with session established
            setTimeout(() => {
                window.location.href = d.redirect || '/otp';
            }, 800);
        } else {
            showAlert(d.message || 'Invalid username or password.', 'error');
            btn.classList.remove('loading');
            btn.textContent = 'Sign In →';
        }
    } catch (err) {
        console.error('[Login Error]', err);
        showAlert('Connection error — is the server running?', 'error');
        btn.classList.remove('loading');
        btn.textContent = 'Sign In →';
    }
};

/**
 * Handle Registration
 */
window.doRegister = async function () {
    const fn = document.getElementById('firstName').value.trim();
    const ln = document.getElementById('lastName').value.trim();
    const un = document.getElementById('username').value.trim();
    const em = document.getElementById('email')?.value.trim() || '';
    const pw = document.getElementById('password').value;
    const cf = document.getElementById('confirm')?.value || '';
    const tc = document.getElementById('terms')?.checked || false;
    const btn = document.getElementById('regBtn');

    if (!fn || !ln || !un || !pw || (cf && pw !== cf)) {
        return showAlert('Please fill in all fields correctly.', 'error');
    }
    
    if (cf && pw !== cf) {
        return showAlert('Passwords do not match.', 'error');
    }
    
    if (!tc && document.getElementById('terms')) {
        return showAlert('Please accept the Terms of Service.', 'error');
    }

    btn.classList.add('loading');
    btn.textContent = 'Creating account…';

    try {
        const r = await fetch('/api/register', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                firstName: fn,
                lastName: ln,
                username: un,
                email: em,
                password: pw,
                confirmPassword: cf
            })
        });

        if (!r.ok) throw new Error('Server error ' + r.status);

        const d = await r.json();
        
        if (d.success) {
            showAlert('Account created! Taking you to your dashboard…', 'success');
            
            // ✅ New users skip OTP — go straight to dashboard
            setTimeout(() => {
                window.location.href = d.redirect || '/dashboard';
            }, 800);
        } else {
            showAlert(d.message || 'Registration failed.', 'error');
            btn.classList.remove('loading');
            btn.textContent = 'Create Account & Go →';
        }
    } catch (err) {
        console.error('[Register Error]', err);
        showAlert('Connection error. Is the server running?', 'error');
        btn.classList.remove('loading');
        btn.textContent = 'Create Account & Go →';
    }
};

/**
 * Handle OTP Verification — with proper redirect on success only
 */
window.doVerifyOTP = async function () {
    const otpInputs = document.querySelectorAll('.dig');
    const otp = Array.from(otpInputs).map(el => el.value).join('');
    const accountId = document.getElementById('accountId')?.value.trim() || '';
    const btn = document.getElementById('verifyBtn');

    if (otp.length < 6) {
        return showAlert('Please enter all 6 digits.', 'error');
    }

    btn.classList.add('loading');
    btn.textContent = 'Verifying with HoneyBound…';

    try {
        const body = { otp };
        if (accountId) body.accountId = accountId;

        const r = await fetch('/api/verify-otp', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(body)
        });

        if (!r.ok) throw new Error('Server error ' + r.status);

        const d = await r.json();

        if (d.success) {
            const modeMsg = d.mode === 'honeybound' 
                ? ' Verified via HoneyBound ✓' 
                : d.mode === 'fallback' 
                ? ' (HoneyBound offline — demo mode)' 
                : '';
            
            showAlert('Identity verified! Welcome to Connectly ✨' + modeMsg, 'success');

            if (d.warning) {
                setTimeout(() => showAlert('⚠️ ' + d.warning, 'warning'), 1000);
            }

            // ✅ FIX: honeytrap sessions also get success:true — redirect them to
            // /fakedashboard silently. Real sessions go to /dashboard.
            setTimeout(() => {
                window.location.href = d.redirect || '/dashboard';
            }, 1200);

        } else {
            showAlert(d.message || 'Invalid OTP. Please try again.', 'error');
            
            // Reset the form but stay on OTP page
            otpInputs.forEach(el => {
                el.value = '';
                el.classList.remove('filled', 'valid');
            });
            otpInputs[0]?.focus();
            
            btn.classList.remove('loading');
            btn.textContent = 'Verify with HoneyBound →';
        }
    } catch (err) {
        console.error('[OTP Verify Error]', err);
        showAlert('Connection error. Make sure the server is running.', 'error');
        btn.classList.remove('loading');
        btn.textContent = 'Verify with HoneyBound →';
    }
};

/**
 * Handle Logout
 */
window.doLogout = async function () {
    try {
        await fetch('/api/logout', { method: 'POST' });
    } catch (err) {
        console.error('[Logout Error]', err);
    }
    window.location.href = '/';
};

/**
 * Dashboard UI helpers
 */
window.toggleLike = function (btn, base) {
    btn.classList.toggle('liked');
    const n = parseInt(base) + (btn.classList.contains('liked') ? 1 : 0);
    btn.innerHTML = (btn.classList.contains('liked') ? '❤️ ' : '🤍 ') + n;
};

window.toggleFollow = function (btn) {
    btn.classList.toggle('following');
    btn.textContent = btn.classList.contains('following') ? 'Following' : 'Follow';
};