# Key/value pairs enforced in /etc/security/faillock.conf (layer 16).
# Format: key=value  or a bare flag. Enabling pam_faillock in the PAM stack is
# done with `authselect enable-feature with-faillock` on RHEL (apply does this
# on a live system); on Ubuntu it belongs to the identity/PAM layer (pending).
# Ref: accounts_passwords_pam_faillock_deny, _unlock_time, _interval
deny=5
fail_interval=900
unlock_time=900
audit
