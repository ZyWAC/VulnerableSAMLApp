<?php
$this->data['header'] = $this->t('{login:user_pass_header}');

if (strlen($this->data['username']) > 0) {
    $this->data['autofocus'] = 'password';
} else {
    $this->data['autofocus'] = 'username';
}
?>

<style>
    body {
        background-color: #f0f9ff !important;
        font-family: 'Segoe UI', system-ui, -apple-system, sans-serif !important;
    }
    .idp-login-wrapper {
        display: flex;
        justify-content: center;
        align-items: center;
        min-height: 70vh;
        padding: 2rem 1rem;
    }
    .idp-login-card {
        background: #ffffff;
        border: 1px solid #e2e8f0;
        border-radius: 1rem;
        box-shadow: 0 4px 24px rgba(14, 165, 233, 0.08);
        max-width: 460px;
        width: 100%;
        overflow: hidden;
    }
    .idp-login-header {
        background: linear-gradient(135deg, #0369a1, #38bdf8);
        padding: 2rem 2rem 1.5rem;
        text-align: center;
        color: #fff;
    }
    .idp-login-header h1 {
        margin: 0.75rem 0 0.25rem;
        font-size: 1.5rem;
        font-weight: 700;
        color: #fff;
    }
    .idp-login-header p {
        margin: 0;
        font-size: 0.85rem;
        opacity: 0.85;
    }
    .idp-login-header img {
        width: 120px;
        height: auto;
        border-radius: 50%;
        border: 3px solid rgba(255,255,255,0.3);
    }
    .idp-login-body {
        padding: 2rem;
    }
    .idp-login-body label {
        display: block;
        font-weight: 600;
        font-size: 0.85rem;
        color: #64748b;
        margin-bottom: 0.35rem;
        text-transform: uppercase;
        letter-spacing: 0.03em;
    }
    .idp-login-body input[type="text"],
    .idp-login-body input[type="password"] {
        width: 100%;
        padding: 0.65rem 0.875rem;
        border: 1px solid #cbd5e1;
        border-radius: 0.5rem;
        font-size: 0.95rem;
        color: #1e293b;
        background: #fff;
        transition: border-color 0.2s, box-shadow 0.2s;
        box-sizing: border-box;
    }
    .idp-login-body input[type="text"]:focus,
    .idp-login-body input[type="password"]:focus {
        outline: none;
        border-color: #0ea5e9;
        box-shadow: 0 0 0 3px rgba(14,165,233,0.15);
    }
    .idp-login-body select {
        width: 100%;
        padding: 0.65rem 0.875rem;
        border: 1px solid #cbd5e1;
        border-radius: 0.5rem;
        font-size: 0.95rem;
        color: #1e293b;
        background: #fff;
    }
    .idp-form-group {
        margin-bottom: 1.25rem;
    }
    .idp-remember {
        display: flex;
        align-items: center;
        gap: 0.5rem;
        margin-top: 0.5rem;
        font-size: 0.85rem;
        color: #64748b;
    }
    .idp-btn-login {
        display: block;
        width: 100%;
        padding: 0.7rem;
        background: linear-gradient(135deg, #0ea5e9, #38bdf8);
        color: #fff;
        border: none;
        border-radius: 0.5rem;
        font-size: 1rem;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s;
        margin-top: 0.5rem;
    }
    .idp-btn-login:hover {
        background: linear-gradient(135deg, #0284c7, #0ea5e9);
        transform: translateY(-1px);
        box-shadow: 0 4px 12px rgba(14,165,233,0.3);
    }
    .idp-error {
        background: #fee2e2;
        color: #dc2626;
        border: 1px solid #fca5a5;
        border-radius: 0.75rem;
        padding: 0.875rem 1rem;
        margin-bottom: 1.25rem;
        font-size: 0.9rem;
    }
    .idp-error strong { display: block; margin-bottom: 0.25rem; }
    .idp-footer {
        text-align: center;
        padding: 1rem 2rem 1.5rem;
        border-top: 1px solid #e2e8f0;
        font-size: 0.8rem;
        color: #94a3b8;
    }
</style>

<div class="idp-login-wrapper">
    <div class="idp-login-card">
        <div class="idp-login-header">
            <img src="/simplesamlphp/resources/welcome.png" alt="Jellystone">
            <h1>Jellystone IDP</h1>
            <p>Identity Provider &mdash; Single Sign-On</p>
        </div>
        <div class="idp-login-body">
            <?php if ($this->data['errorcode'] !== null) { ?>
            <div class="idp-error">
                <strong><?php echo htmlspecialchars($this->t(
                    '{errors:title_'.$this->data['errorcode'].'}',
                    $this->data['errorparams']
                )); ?></strong>
                <span><?php echo htmlspecialchars($this->t(
                    '{errors:descr_'.$this->data['errorcode'].'}',
                    $this->data['errorparams']
                )); ?></span>
            </div>
            <?php } ?>

            <form action="?" method="post" name="f">
                <div class="idp-form-group">
                    <label for="username"><?php echo $this->t('{login:username}'); ?></label>
                    <input id="username" <?php echo ($this->data['forceUsername']) ? 'disabled="disabled"' : ''; ?>
                           type="text" name="username"
                           <?php if (!$this->data['forceUsername']) { echo 'tabindex="1"'; } ?>
                           value="<?php echo htmlspecialchars($this->data['username']); ?>"
                           placeholder="Enter your username">
                    <?php if ($this->data['rememberUsernameEnabled'] && !$this->data['forceUsername']) { ?>
                    <div class="idp-remember">
                        <input type="checkbox" id="remember_username" tabindex="4"
                               <?php echo ($this->data['rememberUsernameChecked']) ? 'checked="checked"' : ''; ?>
                               name="remember_username" value="Yes">
                        <label for="remember_username" style="margin:0; text-transform:none; font-weight:400;"><?php echo $this->t('{login:remember_username}'); ?></label>
                    </div>
                    <?php } ?>
                </div>
                <div class="idp-form-group">
                    <label for="password"><?php echo $this->t('{login:password}'); ?></label>
                    <input id="password" type="password" tabindex="2" name="password" placeholder="Enter your password">
                    <?php if ($this->data['rememberMeEnabled']) { ?>
                    <div class="idp-remember">
                        <input type="checkbox" id="remember_me" tabindex="5"
                               <?php echo ($this->data['rememberMeChecked']) ? 'checked="checked"' : ''; ?>
                               name="remember_me" value="Yes">
                        <label for="remember_me" style="margin:0; text-transform:none; font-weight:400;"><?php echo $this->t('{login:remember_me}'); ?></label>
                    </div>
                    <?php } ?>
                </div>
                <?php if (array_key_exists('organizations', $this->data)) { ?>
                <div class="idp-form-group">
                    <label for="organization"><?php echo $this->t('{login:organization}'); ?></label>
                    <select name="organization" tabindex="3">
                        <?php
                        $selectedOrg = array_key_exists('selectedOrg', $this->data) ? $this->data['selectedOrg'] : null;
                        foreach ($this->data['organizations'] as $orgId => $orgDesc) {
                            if (is_array($orgDesc)) { $orgDesc = $this->t($orgDesc); }
                            $selected = ($orgId === $selectedOrg) ? 'selected="selected" ' : '';
                            echo '<option '.$selected.'value="'.htmlspecialchars($orgId).'">'.htmlspecialchars($orgDesc).'</option>';
                        }
                        ?>
                    </select>
                </div>
                <?php } ?>
                <button id="regularsubmit" class="idp-btn-login"
                        onclick="this.innerText='<?php echo $this->t('{login:processing}'); ?>'; this.disabled=true; this.form.submit(); return true;"
                        tabindex="6" type="submit">
                    <?php echo $this->t('{login:login_button}'); ?>
                </button>
                <?php
                foreach ($this->data['stateparams'] as $name => $value) {
                    echo '<input type="hidden" name="'.htmlspecialchars($name).'" value="'.htmlspecialchars($value).'">';
                }
                ?>
            </form>
        </div>
        <div class="idp-footer">
            Jellystone Identity Provider &mdash; Vulnerable SAML App
            <?php if (!empty($this->data['links'])) { ?>
            <div style="margin-top: 0.5rem;">
                <?php foreach ($this->data['links'] as $l) {
                    echo '<a href="'.htmlspecialchars($l['href']).'" style="color: #0ea5e9;">'.htmlspecialchars($this->t($l['text'])).'</a> ';
                } ?>
            </div>
            <?php } ?>
        </div>
    </div>
</div>
