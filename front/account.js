// ═══════════════════════════════════════════════════════════════════
// QuickFW Account — password change with strength meter
// ═══════════════════════════════════════════════════════════════════
(function() {
QFW.registerPage('account', {
  init(page) {
    page.innerHTML = `
      <div class="page-header"><div><h1>Account</h1><p class="page-sub">Manage your account settings</p></div></div>
      <div class="card account-card">
        <div class="card-header"><h2>Change Password</h2></div>
        <div class="card-body">
          <div class="form-grid" style="max-width:400px;">
            <div class="form-group full-width"><label>Current Password</label><input type="password" id="acc-current"></div>
            <div class="form-group full-width"><label>New Password</label><input type="password" id="acc-new" oninput="this.dispatchEvent(new Event('strength'))"><div class="strength-meter"><div class="strength-fill" id="acc-strength"></div></div><div class="strength-text" id="acc-strength-text"></div></div>
            <div class="form-group full-width"><label>Confirm New Password</label><input type="password" id="acc-confirm"></div>
          </div>
          <div style="margin-top:16px;"><button class="btn-primary" id="acc-save-btn">Change Password</button></div>
        </div>
      </div>
    `;

    const newPass = page.querySelector('#acc-new');
    const strengthFill = page.querySelector('#acc-strength');
    const strengthText = page.querySelector('#acc-strength-text');
    newPass.addEventListener('strength', () => {
      const val = newPass.value;
      let score = 0;
      if (val.length >= 8) score++;
      if (val.length >= 12) score++;
      if (/[A-Z]/.test(val) && /[a-z]/.test(val)) score++;
      if (/[0-9]/.test(val)) score++;
      if (/[^A-Za-z0-9]/.test(val)) score++;
      const levels = ['','weak','fair','good','strong','strong'];
      const labels = ['','Weak','Fair','Good','Strong','Strong'];
      const colors = ['','var(--danger)','var(--warning)','#eab308','var(--success)','var(--success)'];
      strengthFill.className = 'strength-fill ' + (levels[score]||'');
      strengthText.textContent = val ? labels[score]||'' : '';
      strengthText.style.color = colors[score]||'';
    });
    newPass.oninput = () => newPass.dispatchEvent(new Event('strength'));

    page.querySelector('#acc-save-btn').onclick = () => {
      const current = page.querySelector('#acc-current').value;
      const newPw = page.querySelector('#acc-new').value;
      const confirm = page.querySelector('#acc-confirm').value;
      if (!current) { QFW.toast('Current password required','error'); return; }
      if (newPw.length < 8) { QFW.toast('New password must be at least 8 characters','error'); return; }
      if (newPw !== confirm) { QFW.toast('Passwords do not match','error'); return; }
      QFW.api.post('/api/auth/password', { current_password:current, new_password:newPw })
        .then(() => { QFW.toast('Password changed successfully','success'); page.querySelector('#acc-current').value=''; page.querySelector('#acc-new').value=''; page.querySelector('#acc-confirm').value=''; strengthFill.className='strength-fill'; strengthText.textContent=''; })
        .catch(e => QFW.toast('Failed: '+e.message,'error'));
    };
  },
  load() {}
});
})();
