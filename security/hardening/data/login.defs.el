# Key/value pairs enforced in /etc/login.defs by el-harden-apply (layer 16).
# Format: KEY VALUE [family]   family = any|debian|rhel (default any)
# Local accounts are break-glass/bootstrap only; directory accounts follow the IdP.
# Ref: accounts_maximum_age_login_defs, accounts_minimum_age_login_defs,
#      accounts_password_warn_age_login_defs, accounts_umask_etc_login_defs,
#      set_password_hashing_algorithm_logindefs
PASS_MAX_DAYS 365
PASS_MIN_DAYS 1
PASS_WARN_AGE 14
UMASK 027
LOGIN_RETRIES 3
LOGIN_TIMEOUT 60
# yescrypt is the Ubuntu default; RHEL keeps SHA512 (FIPS-compatible)
ENCRYPT_METHOD YESCRYPT debian
ENCRYPT_METHOD SHA512 rhel
