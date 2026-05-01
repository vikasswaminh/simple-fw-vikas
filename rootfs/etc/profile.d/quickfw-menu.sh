# Show the QuickFW console menu when root logs in interactively on a tty.
#
# Skip:
#   - non-interactive shells (scp, sftp, automation)
#   - non-tty sessions
#   - not-root users
#   - the quickfw-setup wizard process itself (its child shell would loop)
#   - when QUICKFW_NOMENU=1 is set (escape hatch for debugging)
#
# Menu option 4 ("Shell") just exits the menu back to the caller, which
# returns control to bash without re-invoking the menu (bash sources
# profile.d only once per login).

if [ -z "${QUICKFW_MENU_SHOWN:-}" ] \
   && [ "$(id -u)" = "0" ] \
   && [ -t 0 ] && [ -t 1 ] \
   && [ -z "${QUICKFW_NOMENU:-}" ] \
   && [ -x /usr/local/sbin/quickfw-menu ]; then
    export QUICKFW_MENU_SHOWN=1
    /usr/local/sbin/quickfw-menu
fi
