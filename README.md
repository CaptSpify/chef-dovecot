Description
===========

This cookbook is to install and configure dovecot. It will be using all of the default options. I will have the variables for other systems, but I will be focusing on Debian. This has NOT been tested on RedHat/CentOS/Suse/etc.
I'd imagine Ubuntu would work, but use at your own risk.

Requirements
============

Platform:

* Debian

Attributes
==========
 Default attributes for dovecot configuration. 
 See http://wiki.dovecot.org/QuickConfiguration for help.

 Protocols we want to be serving:imap imaps pop3 pop3s managesieve
 If you only want to use dovecot-auth, you can set this to "none".

 Base directory where to store runtime data.
default[:dovecot][:base_dir] = '/var/run/dovecot'

 Protocols we want to be serving:imap imaps pop3 pop3s managesieve
 If you only want to use dovecot-auth, you can set this to "none".
default[:dovecot][:protocols] = none

 A space separated list of IP or host addresses where to listen in for
 connections. "*" listens in all IPv4 interfaces. "[::]" listens in all IPv6
 interfaces. Use "*, [::]" for listening both IPv4 and IPv6.

 If you want to specify ports for each service, you will need to configure
 these settings inside the protocol imap/pop3/managesieve { ... } section,
 so you can specify different ports for IMAP/POP3/MANAGESIEVE. For example:
default[:dovecot][:imap_listen] = '*'
default[:dovecot][:ssl_imap_listen] = '*'
default[:dovecot][:pop3_listen] = '*'
default[:dovecot][:managesieve_listen] = '*'
default[:dovecot][:listen] = '*'

 Disable LOGIN command and all other plaintext authentications unless
 SSL/TLS is used (LOGINDISABLED capability). Note that if the remote IP
 matches the local IP (ie. you're connecting from the same computer), the
 connection is considered secure and plaintext authentication is allowed.
default[:dovecot][:disable_plaintext_auth] = 'yes'

 Should all IMAP and POP3 processes be killed when Dovecot master process
 shuts down. Setting this to "no" means that Dovecot can be upgraded without
 forcing existing client connections to close (although that could also be
 a problem if the upgrade is eg. because of a security fix). This however
 means that after master process has died, the client processes can't write
 to log files anymore.
default[:dovecot][:shutdown_clients] = 'yes'


 Logging


 Log file to use for error messages, instead of sending them to syslog.
 /dev/stderr can be used to log into stderr.
default[:dovecot][:log_path] = ''

 Log file to use for informational and debug messages.
 Default is the same as log_path.
default[:dovecot][:info_log_path] = ''

 Prefix for each line written to log file. % codes are in strftime(3)
 format.
default[:dovecot][:log_timestamp] = '"%Y-%m-%d %H:%M:%S "'

 Syslog facility to use if you're logging to syslog. Usually if you don't
 want to use "mail", you'll use local0..local7. Also other standard
 facilities are supported.
default[:dovecot][:syslog_facility] = 'mail'


 SSL settings


 IP or host address where to listen in for SSL connections. Remember to also
 add imaps and/or pop3s to protocols setting. Defaults to same as "listen"
 setting if not specified.
default[:dovecot][:ssl_listen] = ''

 SSL/TLS support:yes, no, required. </usr/share/doc/dovecot-common/wiki/SSL.txt>
default[:dovecot][:ssl] = 'yes'

 PEM encoded X.509 SSL/TLS certificate and private key. They're opened before
 dropping root privileges, so keep the key file unreadable by anyone but
 root.
default[:dovecot][:ssl_cert_file] = '/etc/ssl/certs/dovecot.pem'
default[:dovecot][:ssl_key_file] = '/etc/ssl/private/dovecot.pem'

 If key file is password protected, give the password here. Alternatively
 give it when starting dovecot with -p parameter. Since this file is often
 world-readable, you may want to place this setting instead to a different
 root owned 0600 file by using !include_try <path>.
default[:dovecot][:ssl_key_password] = ''

 File containing trusted SSL certificate authorities. Set this only if you
 intend to use ssl_verify_client_cert=yes. The CAfile should contain the
 CA-certificate(s) followed by the matching CRL(s).
default[:dovecot][:ssl_ca_file] = ''

 Request client to send a certificate. If you also want to require it, set
 ssl_require_client_cert=yes in auth section.
default[:dovecot][:ssl_verify_client_cert] = 'no'

 Which field from certificate to use for username. commonName and
 x500UniqueIdentifier are the usual choices. You'll also need to set
default[:dovecot][:ssl_username_from_cert] = 'yes.'
default[:dovecot][:ssl_cert_username_field] = 'commonName'

 How often to regenerate the SSL parameters file. Generation is quite CPU
 intensive operation. The value is in hours, 0 disables regeneration
 entirely.
default[:dovecot][:ssl_parameters_regenerate] = '168'

 SSL ciphers to use
default[:dovecot][:ssl_cipher_list] = 'ALL:!LOW:!SSLv2'

 Show protocol level SSL errors.
default[:dovecot][:verbose_ssl] = 'no'


 Login processes


 </usr/share/doc/dovecot-common/wiki/LoginProcess.txt>

 Directory where authentication process places authentication UNIX sockets
 which login needs to be able to connect to. The sockets are created when
 running as root, so you don't have to worry about permissions. Note that
 everything in this directory is deleted when Dovecot is started.
default[:dovecot][:login_dir] = '/var/run/dovecot/login'

 chroot login process to the login_dir. Only reason not to do this is if you
 wish to run the whole Dovecot without roots. </usr/share/doc/dovecot-common/wiki/Rootless.txt>
default[:dovecot][:login_chroot] = 'yes'

 User to use for the login process. Create a completely new user for this,
 and don't use it anywhere else. The user must also belong to a group where
 only it has access, it's used to control access for authentication process.
 Note that this user is NOT used to access mails. </usr/share/doc/dovecot-common/wiki/UserIds.txt>
default[:dovecot][:login_user] = 'dovecot'

 Set max. process size in megabytes. If you don't use
 login_process_per_connection you might need to grow this.
default[:dovecot][:login_process_size] = '64'

 Should each login be processed in it's own process (yes), or should one
 login process be allowed to process multiple connections (no)? Yes is more
 secure, espcially with SSL/TLS enabled. No is faster since there's no need
 to create processes all the time.
default[:dovecot][:login_process_per_connection] = 'yes'

 Number of login processes to keep for listening new connections.
default[:dovecot][:login_processes_count] = '3'

 Maximum number of login processes to create. The listening process count
 usually stays at login_processes_count, but when multiple users start logging
 in at the same time more extra processes are created. To prevent fork-bombing
 we check only once in a second if new processes should be created - if all
 of them are used at the time, we double their amount until the limit set by
 this setting is reached.
default[:dovecot][:login_max_processes_count] = '128'

 Maximum number of connections allowed per each login process. This setting
 is used only if login_process_per_connection=no. Once the limit is reached,
 the process notifies master so that it can create a new login process.
default[:dovecot][:login_max_connections] = '256'

 Greeting message for clients.
default[:dovecot][:login_greeting] = 'Dovecot ready.'

 Space separated list of trusted network ranges. Connections from these
 IPs are allowed to override their IP addresses and ports (for logging and
 for authentication checks). disable_plaintext_auth is also ignored for
 these networks. Typically you'd specify your IMAP proxy servers here.
default[:dovecot][:login_trusted_networks] = ''

 Space-separated list of elements we want to log. The elements which have
 a non-empty variable value are joined together to form a comma-separated
 string.
default[:dovecot][:login_log_format_elements] = 'user=<%u> method=%m rip=%r lip=%l %c'

 Login log format. %$ contains login_log_format_elements string, %s contains
 the data we want to log.
default[:dovecot][:login_log_format] = '%$:%s'


 Mailbox locations and namespaces


 Location for users' mailboxes. This is the same as the old default_mail_env
 setting. The default is empty, which means that Dovecot tries to find the
 mailboxes automatically. This won't work if the user doesn't have any mail
 yet, so you should explicitly tell Dovecot the full location.

 If you're using mbox, giving a path to the INBOX file (eg. /var/mail/%u)
 isn't enough. You'll also need to tell Dovecot where the other mailboxes are
 kept. This is called the "root mail directory", and it must be the first
 path given in the mail_location setting.

 There are a few special variables you can use, eg.:

   %u - username
   %n - user part in user@domain, same as %u if there's no domain
   %d - domain part in user@domain, empty if there's no domain
   %h - home directory

 See </usr/share/doc/dovecot-common/wiki/Variables.txt> for full list.
 Some examples:

default[:dovecot][:mail_location] = 'maildir:~/Maildir'
default[:dovecot][:mail_location] = 'mbox:~/mail:INBOX=/var/mail/%u'
default[:dovecot][:mail_location] = 'mbox:/var/mail/%d/%1n/%n:INDEX=/var/indexes/%d/%1n/%n'

 </usr/share/doc/dovecot-common/wiki/MailLocation.txt>

default[:dovecot][:mail_location] = ''

 If you need to set multiple mailbox locations or want to change default
 namespace settings, you can do it by defining namespace sections.

 You can have private, shared and public namespaces. Private namespaces
 are for user's personal mails. Shared namespaces are for accessing other
 users' mailboxes that have been shared. Public namespaces are for shared
 mailboxes that are managed by sysadmin. If you create any shared or public
 namespaces you'll typically want to enable ACL plugin also, otherwise all
 users can access all the shared mailboxes, assuming they have permissions
 on filesystem level to do so.

 REMEMBER:If you add any namespaces, the default namespace must be added
 explicitly, ie. mail_location does nothing unless you have a namespace
 without a location setting. Default namespace is simply done by having a
 namespace with empty prefix.
   # Hierarchy separator to use. You should use the same separator for all
   # namespaces or some clients get confused. '/' is usually a good one.
   # The default however depends on the underlying mail storage format.
default[:dovecot][:private_private] = ''

   # Prefix required to access this namespace. This needs to be different for
   # all namespaces. For example "Public/".
default[:dovecot][:private_separator] = ''

   # Physical location of the mailbox. This is in same format as
   # mail_location, which is also the default for it.
default[:dovecot][:private_location] = ''

   # There can be only one INBOX, and this setting defines which namespace
   # has it.
default[:dovecot][:private_inbox] = 'no'

   # If namespace is hidden, it's not advertised to clients via NAMESPACE
   # extension. You'll most likely also want to set list=no. This is mostly
   # useful when converting from another server with different namespaces which
   # you want to deprecate but still keep working. For example you can create
   # hidden namespaces with prefixes "~/mail/", "~%u/mail/" and "mail/".
default[:dovecot][:hidden] = 'yes'

   # Show the mailboxes under this namespace with LIST command. This makes the
   # namespace visible for clients that don't support NAMESPACE extension.
   # "children" value lists child mailboxes, but hides the namespace prefix.
default[:dovecot][:list] = 'yes'

   # Namespace handles its own subscriptions. If set to "no", the parent
   # namespace handles them (empty prefix should always have this as "yes")
default[:dovecot][:subscriptions] = 'yes'

 Example shared namespace configuration
default[:dovecot][:shared_separator] = '/'

   # Mailboxes are visible under "shared/user@domain/"
   # %%n, %%d and %%u are expanded to the destination user.
default[:dovecot][:shared_prefix] = 'shared/%%u/'

   # Mail location for other users' mailboxes. Note that %variables and ~/
   # expands to the logged in user's data. %%n, %%d, %%u and %%h expand to the
   # destination user's data.
default[:dovecot][:shared_location] = 'maildir:%%h/Maildir:INDEX=~/Maildir/shared/%%u'

   # Use the default namespace for saving subscriptions.
default[:dovecot][:shared_subscriptions] = 'no'

   # List the shared/ namespace only if there are visible shared mailboxes.
default[:dovecot][:shared_list] = 'children'

 System user and group used to access mails. If you use multiple, userdb
 can override these by returning uid or gid fields. You can use either numbers
 or names. </usr/share/doc/dovecot-common/wiki/UserIds.txt>
default[:dovecot][:mail_uid] = ''

default[:dovecot][:mail_gid] = ''

 Group to enable temporarily for privileged operations. Currently this is
 used only with INBOX when either its initial creation or dotlocking fails.
 Typically this is set to "mail" to give access to /var/mail.

 Grant access to these supplementary groups for mail processes. Typically
 these are used to set up access to shared mailboxes. Note that it may be
 dangerous to set these if users can create symlinks (e.g. if "mail" group is
 set here, ln -s /var/mail ~/mail/var could allow a user to delete others'
 mailboxes, or ln -s /secret/shared/box ~/mail/mybox would allow reading it).
default[:dovecot][:mail_access_groups] = ''

 Allow full filesystem access to clients. There's no access checks other than
 what the operating system does for the active UID/GID. It works with both
 maildir and mboxes, allowing you to prefix mailboxes names with eg. /path/
 or ~user/.
default[:dovecot][:mail_full_filesystem_access] = 'no'


 Mail processes


 Enable mail process debugging. This can help you figure out why Dovecot
 isn't finding your mails.
default[:dovecot][:mail_debug] = 'no'

 Log prefix for mail processes. See </usr/share/doc/dovecot-common/wiki/Variables.txt>
 for list of possible variables you can use.
default[:dovecot][:mail_log_prefix] = '"%Us(%u):"'

 Max. number of lines a mail process is allowed to log per second before it's
 throttled. 0 means unlimited. Typically there's no need to change this
 unless you're using mail_log plugin, which may log a lot. This setting is
default[:dovecot][:] = ''
default[:dovecot][:mail_log_max_lines_per_sec] = '10'

 Don't use mmap() at all. This is required if you store indexes to shared
 filesystems (NFS or clustered filesystem).
default[:dovecot][:mmap_disable] = 'no'

 Rely on O_EXCL to work when creating dotlock files. NFS supports O_EXCL
 since version 3, so this should be safe to use nowadays by default.
default[:dovecot][:dotlock_use_excl] = 'yes'

 Don't use fsync() or fdatasync() calls. This makes the performance better
 at the cost of potential data loss if the server (or the file server)
 goes down.
default[:dovecot][:fsync_disable] = 'no'

 Mail storage exists in NFS. Set this to yes to make Dovecot flush NFS caches
 whenever needed. If you're using only a single mail server this isn't needed.
default[:dovecot][:mail_nfs_storage] = 'no'
 Mail index files also exist in NFS. Setting this to yes requires
default[:dovecot][:mail_nfs_index] = 'no'

 Locking method for index files. Alternatives are fcntl, flock and dotlock.
 Dotlocking uses some tricks which may create more disk I/O than other locking
 methods. NFS users:flock doesn't work, remember to change mmap_disable.
default[:dovecot][:lock_method] = 'fcntl'

 Drop all privileges before exec()ing the mail process. This is mostly
 meant for debugging, otherwise you don't get core dumps. It could be a small
 security risk if you use single UID for multiple users, as the users could
 ptrace() each others processes then.
default[:dovecot][:mail_drop_priv_before_exec] = 'no'

 Show more verbose process titles (in ps). Currently shows user name and
 IP address. Useful for seeing who are actually using the IMAP processes
 (eg. shared mailboxes or if same uid is used for multiple accounts).
default[:dovecot][:verbose_proctitle] = 'no'

 Valid UID range for users, defaults to 500 and above. This is mostly
 to make sure that users can't log in as daemons or other system users.
 Note that denying root logins is hardcoded to dovecot binary and can't
 be done even if first_valid_uid is set to 0.
default[:dovecot][:first_valid_uid] = '500'
default[:dovecot][:last_valid_uid] = '0'

 Valid GID range for users, defaults to non-root/wheel. Users having
 non-valid GID as primary group ID aren't allowed to log in. If user
 belongs to supplementary groups with non-valid GIDs, those groups are
 not set.
default[:dovecot][:first_valid_gid] = '1'
default[:dovecot][:last_valid_gid] = '0'

 Maximum number of running mail processes. When this limit is reached,
 new users aren't allowed to log in.
default[:dovecot][:max_mail_processes] = '512'

 Set max. process size in megabytes. Most of the memory goes to mmap()ing
 files, so it shouldn't harm much even if this limit is set pretty high.
default[:dovecot][:mail_process_size] = '256'

 Maximum allowed length for mail keyword name. It's only forced when trying
 to create new keywords.
default[:dovecot][:mail_max_keyword_length] = '50'

 ':' separated list of directories under which chrooting is allowed for mail
 processes (ie. /var/mail will allow chrooting to /var/mail/foo/bar too).
 This setting doesn't affect login_chroot, mail_chroot or auth chroot
 settings. If this setting is empty, "/./" in home dirs are ignored.
 WARNING:Never add directories here which local users can modify, that
 may lead to root exploit. Usually this should be done only if you don't
 allow shell access for users. </usr/share/doc/dovecot-common/wiki/Chrooting.txt>
default[:dovecot][:valid_chroot_dirs] = ''

 Default chroot dir
ectory for mail processes. This can be overridden for
 specific users in user database by giving /./ in user's home directory
 (eg. /home/./user chroots into /home). Note that usually there is no real
 need to do chrooting, Dovecot doesn't allow users to access files outside
 their mail directory anyway. If your home directories are prefixed with
 the chroot directory, append "/." to mail_chroot. </usr/share/doc/dovecot-common/wiki/Chrooting.txt>
default[:dovecot][:mail_chroot] = ''


 Mailbox han
dling optimizations


 The minimum number of mails in a mailbox before updates are done to cache
 file. This allows optimizing Dovecot's behavior to do less disk writes at
 the cost of more disk reads.
default[:dovecot][:mail_cache_min_mail_count] = '0'

 When IDLE command is running, mailbox is checked once in a while to see if
 there are any new mails or other changes. This setting defines the minimum
 time in seconds to wait between those checks. Dovecot can also use dnotify,
 inotify and kqueue to find out immediately when changes occur.
default[:dovecot][:mailbox_idle_check_interval] = '30'

 Save mails with CR+LF instead of plain LF. This makes sending those mails
 take less CPU, especially with sendfile() syscall with Linux and FreeBSD.
 But it also creates a bit more disk I/O which may just make it slower.
 Also note that if other software reads the mboxes/maildirs, they may handle
 the extra CRs wrong and cause problems.
default[:dovecot][:mail_save_crlf] = 'no'


 Maildir-specific settings


 By default LIST command returns all entries in maildir beginning with a dot.
 Enabling this option makes Dovecot return only entries which are directories.
 This is done by stat()ing each entry, so it causes more disk I/O.
 (For systems setting struct dirent->d_type, this check is free and it's
 done always regardless of this setting)
default[:dovecot][:maildir_stat_dirs] = 'no'

 When copying a message, do it with hard links whenever possible. This makes
 the performance much better, and it's unlikely to have any side effects.
default[:dovecot][:maildir_copy_with_hardlinks] = 'yes'

 When copying a message, try to preserve the base filename. Only if the
 destination mailbox already contains the same name (ie. the mail is being
 copied there twice), a new name is given. The destination filename check is
 done only by looking at dovecot-uidlist file, so if something outside
 Dovecot does similar filename preserving copies, you may run into problems.
 NOTE:This setting requires maildir_copy_with_hardlinks = yes to work
default[:dovecot][:maildir_copy_preserve_filename] = 'no'

 Assume Dovecot is the only MUA accessing Maildir:Scan cur/ directory only
 when its mtime changes unexpectedly or when we can't find the mail otherwise.
default[:dovecot][:maildir_very_dirty_syncs] = 'no'


 mbox-specific settings


 Which locking methods to use for locking mbox. There are four available:
  dotlock:Create <mailbox>.lock file. This is the oldest and most NFS-safe
           solution. If you want to use /var/mail/ like directory, the users
           will need write access to that directory.
  dotlock_try:Same as dotlock, but if it fails because of permissions or
               because there isn't enough disk space, just skip it.
  fcntl  :Use this if possible. Works with NFS too if lockd is used.
  flock  :May not exist in all systems. Doesn't work with NFS.
  lockf  :May not exist in all systems. Doesn't work with NFS.

 You can use multiple locking methods; if you do the order they're declared
 in is important to avoid deadlocks if other MTAs/MUAs are using multiple
 locking methods as well. Some operating systems don't allow using some of
 them simultaneously.

 The Debian value for mbox_write_locks differs from upstream Dovecot. It is
 changed to be compliant with Debian Policy (section 11.6) for NFS safety.
default[:dovecot][:Dovecot] = 'dotlock fcntl'
default[:dovecot][:Debian] = 'fcntl dotlock'

default[:dovecot][:mbox_read_locks] = 'fcntl'
default[:dovecot][:mbox_write_locks] = 'fcntl dotlock'

 Maximum time in seconds to wait for lock (all of them) before aborting.
default[:dovecot][:mbox_lock_timeout] = '300'

 If dotlock exists but the mailbox isn't modified in any way, override the
 lock file after this many seconds.
default[:dovecot][:mbox_dotlock_change_timeout] = '120'

 When mbox changes unexpectedly we have to fully read it to find out what
 changed. If the mbox is large this can take a long time. Since the change
 is usually just a newly appended mail, it'd be faster to simply read the
 new mails. If this setting is enabled, Dovecot does this but still safely
 fallbacks to re-reading the whole mbox file whenever something in mbox isn't
 how it's expected to be. The only real downside to this setting is that if
 some other MUA changes message flags, Dovecot doesn't notice it immediately.
 Note that a full sync is done with SELECT, EXAMINE, EXPUNGE and CHECK
 commands.
default[:dovecot][:mbox_dirty_syncs] = 'yes'

 Like mbox_dirty_syncs, but don't do full syncs even with SELECT, EXAMINE,
 EXPUNGE or CHECK commands. If this is set, mbox_dirty_syncs is ignored.
default[:dovecot][:mbox_very_dirty_syncs] = 'no'

 Delay writing mbox headers until doing a full write sync (EXPUNGE and CHECK
 commands and when closing the mailbox). This is especially useful for POP3
 where clients often delete all mails. The downside is that our changes
 aren't immediately visible to other MUAs.
default[:dovecot][:mbox_lazy_writes] = 'yes'

 If mbox size is smaller than this (in kilobytes), don't write index files.
 If an index file already exists it's still read, just not updated.
default[:dovecot][:mbox_min_index_size] = '0'


 dbox-specific settings


 Maximum dbox file size in kilobytes until it's rotated.
default[:dovecot][:dbox_rotate_size] = '2048'

 Minimum dbox file size in kilobytes before it's rotated
 (overrides dbox_rotate_days)
default[:dovecot][:dbox_rotate_min_size] = '16'

 Maximum dbox file age in days until it's rotated. Day always begins from
default[:dovecot][:midnight] = 'today, 2 = yesterday, etc. 0 = check disabled.'
default[:dovecot][:dbox_rotate_days] = '0'


 IMAP specific settings


 Login executable location.
default[:dovecot][:imap_login_executable] = '/usr/lib/dovecot/imap-login'

 IMAP executable location. Changing this allows you to execute other
 binaries before the imap process is executed.

 This would write rawlogs into user's ~/dovecot.rawlog/, if it exists:
default[:dovecot][:imap_mail_executable] = '/usr/lib/dovecot/rawlog /usr/lib/dovecot/imap'
 </usr/doc/dovecot-common/wiki/Debugging.Rawlog.txt>

 This would attach gdb into the imap process and write backtraces into
 /tmp/gdbhelper.* files:
default[:dovecot][:imap_mail_executable] = '/usr/lib/dovecot/gdbhelper /usr/lib/dovecot/imap'

default[:dovecot][:imap_mail_executable] = '/usr/lib/dovecot/imap'

 Maximum IMAP command line length in bytes. Some clients generate very long
 command lines with huge mailboxes, so you may need to raise this if you get
 "Too long argument" or "IMAP command line too large" errors often.
default[:dovecot][:imap_max_line_length] = '65536'

 Maximum number of IMAP connections allowed for a user from each IP address.
 NOTE:The username is compared case-sensitively.
default[:dovecot][:imap_mail_max_userip_connections] = '10'

 Support for dynamically loadable plugins. mail_plugins is a space separated
 list of plugins to load.
default[:dovecot][:imap_mail_plugins] = ''
default[:dovecot][:imap_mail_plugin_dir] = '/usr/lib/dovecot/modules/imap'

 IMAP logout format string:
  %i - total number of bytes read from client
  %o - total number of bytes sent to client
default[:dovecot][:imap_logout_format] = 'bytes=%i/%o'

 Override the IMAP CAPABILITY response.
default[:dovecot][:imap_capability] = ''

 How many seconds to wait between "OK Still here" notifications when
 client is IDLEing.
default[:dovecot][:imap_idle_notify_interval] = '120'

 ID field names and values to send to clients. Using * as the value makes
 Dovecot use the default value. The following fields have default values
 currently:name, version, os, os-version, support-url, support-email.
default[:dovecot][:imap_id_send] = ''

 ID fields sent by client to log. * means everything.
default[:dovecot][:imap_id_log] = ''

 Workarounds for various client bugs:
   delay-newmail:
     Send EXISTS/RECENT new mail notifications only when replying to NOOP
     and CHECK commands. Some clients ignore them otherwise, for example OSX
     Mail (<v2.1). Outlook Express breaks more badly though, without this it
     may show user "Message no longer in server" errors. Note that OE6 still
     breaks even with this workaround if synchronization is set to
     "Headers Only".
   netscape-eoh:
     Netscape 4.x breaks if message headers don't end with the empty "end of
     headers" line. Normally all messages have this, but setting this
     workaround makes sure that Netscape never breaks by adding the line if
     it doesn't exist. This is done only for FETCH BODY[HEADER.FIELDS..]
     commands. Note that RFC says this shouldn't be done.
   tb-extra-mailbox-sep:
     With mbox storage a mailbox can contain either mails or submailboxes,
     but not both. Thunderbird separates these two by forcing server to
     accept '/' suffix in mailbox names in subscriptions list.
 The list is space-separated.
default[:dovecot][:imap_client_workarounds] = ''


 POP3 specific settings


  # Login executable location.
default[:dovecot][:pop3_login_executable] = '/usr/lib/dovecot/pop3-login'

  # POP3 executable location. See IMAP's mail_executable above for examples
  # how this could be changed.
default[:dovecot][:pop3_mail_executable] = '/usr/lib/dovecot/pop3'

  # Don't try to set mails non-recent or seen with POP3 sessions. This is
  # mostly intended to reduce disk I/O. With maildir it doesn't move files
  # from new/ to cur/, with mbox it doesn't write Status-header.
default[:dovecot][:pop3_no_flag_updates] = 'no'

  # Support LAST command which exists in old POP3 specs, but has been removed
  # from new ones. Some clients still wish to use this though. Enabling this
  # makes RSET command clear all \Seen flags from messages.
default[:dovecot][:pop3_enable_last] = 'no'

  # If mail has X-UIDL header, use it as the mail's UIDL.
default[:dovecot][:pop3_reuse_xuidl] = 'no'

  # Keep the mailbox locked for the entire POP3 session.
default[:dovecot][:pop3_lock_session] = 'no'

  # POP3 UIDL (unique mail identifier) format to use. You can use following
  # variables, along with the variable modifiers described in
  # </usr/share/doc/dovecot-common/wiki/Variables.txt> (e.g. %Uf for the
  # filename in uppercase)

  %v - Mailbox's IMAP UIDVALIDITY
  #  %u - Mail's IMAP UID
  #  %m - MD5 sum of the mailbox headers in hex (mbox only)
  #  %f - filename (maildir only)
  #
  # If you want UIDL compatibility with other POP3 servers, use:
  #  UW's ipop3d         :%08Xv%08Xu
  #  Courier             :%f or %v-%u (both might be used simultaneosly)
  #  Dovecot v0.99.x     :%v.%u
  #  tpop3d              :%Mf
  #
  # Note that Outlook 2003 seems to have problems with %v.%u format which was
  # Dovecot's default, so if you're building a new server it would be a good
  # idea to change this. %08Xu%08Xv should be pretty fail-safe.
  #

  # Permanently save UIDLs sent to POP3 clients, so pop3_uidl_format changes
  # won't change those UIDLs. Currently this works only with Maildir.
default[:dovecot][:pop3_save_uidl] = 'no'

  # POP3 logout format string:
  #  %i - total number of bytes read from client
  #  %o - total number of bytes sent to client
  #  %t - number of TOP commands
  #  %p - number of bytes sent to client as a result of TOP command
  #  %r - number of RETR commands
  #  %b - number of bytes sent to client as a result of RETR command
  #  %d - number of deleted messages
  #  %m - number of messages (before deletion)
  #  %s - mailbox size in bytes (before deletion)
default[:dovecot][:pop3_logout_format] = 'top=%t/%p, retr=%r/%b, del=%d/%m, size=%s'

  # Maximum number of POP3 connections allowed for a user from each IP address.
  # NOTE:The username is compared case-sensitively.
default[:dovecot][:pop3_mail_max_userip_connections] = '3'

  # Support for dynamically loadable plugins. mail_plugins is a space separated
  # list of plugins to load.
default[:dovecot][:pop3_mail_plugins] = ''
default[:dovecot][:pop3_mail_plugin_dir] = '/usr/lib/dovecot/modules/popdefault[:dovecot][:pop3_mail_plugins] = ''3'

  # Workarounds for various client bugs:
  #   outlook-no-nuls:
  #     Outlook and Outlook Express hang if mails contain NUL characters.
  #     This setting replaces them with 0x80 character.
  #   oe-ns-eoh:
  #     Outlook Express and Netscape Mail breaks if end of headers-line is
  #     missing. This option simply sends it if it's missing.
  # The list is space-separated.
default[:dovecot][:pop3_client_workarounds] = ''


 ManageSieve specific settings


  # Login executable location.
default[:dovecot][:managesieve_login_executable] = '/usr/lib/dovecot/managesieve-login'

  # ManageSieve executable location. See IMAP's mail_executable above for
  # examples how this could be changed.
default[:dovecot][:managesieve_mail_executable] = '/usr/lib/dovecot/managesieve'

  # Maximum ManageSieve command line length in bytes. This setting is
  # directly borrowed from IMAP. But, since long command lines are very
  # unlikely with ManageSieve, changing this will not be very useful.
default[:dovecot][:managesieve_max_line_length] = '65536'

  # ManageSieve logout format string:
  #  %i - total number of bytes read from client
  #  %o - total number of bytes sent to client
default[:dovecot][:managesieve_logout_format] = 'bytes=%i/%o'

  # If, for some inobvious reason, the sieve_storage remains unset, the
  # ManageSieve daemon uses the specification of the mail_location to find out
  # where to store the sieve files (see explaination in README.managesieve).
  # The example below, when uncommented, overrides any global mail_location
  # specification and stores all the scripts in '~/mail/sieve' if sieve_storage
  # is unset. However, you should always use the sieve_storage setting.
default[:dovecot][:managesieve_mail_location] = 'mbox:~/mail'

  # To fool ManageSieve clients that are focused on timesieved you can
  # specify the IMPLEMENTATION capability that the dovecot reports to clients
  # (default:"dovecot").
default[:dovecot][:managesieve_implementation_string] = 'Cyrus timsieved v2.2.13'


 LDA specific settings


  # Address to use when sending rejection mails (e.g. postmaster@example.com).
default[:dovecot][:lda_postmaster_address] = ''

  # Hostname to use in various parts of sent mails, eg. in Message-Id.
  # Default is the system's real hostname.
default[:dovecot][:lda_hostname] = ''

  # Support for dynamically loadable plugins. mail_plugins is a space separated
  # list of plugins to load.
default[:dovecot][:lda_mail_plugins] = ''
default[:dovecot][:lda_mail_plugin_dir] = '/usr/lib/dovecot/modules/lddefault[:dovecot][:lda_mail_plugins] = ''a'

  # If user is over quota, return with temporary failure instead of
  # bouncing the mail.
default[:dovecot][:lda_quota_full_tempfail] = 'no'

  # Format to use for logging mail deliveries. You can use variables:
  #  %$ - Delivery status message (e.g. "saved to INBOX")
  #  %m - Message-ID
  #  %s - Subject
  #  %f - From address
default[:dovecot][:lda_deliver_log_format] = 'msgid=%m:%$'

  # Binary to use for sending mails.
default[:dovecot][:lda_sendmail_path] = '/usr/sbin/sendmail'

  # Subject:header to use for rejection mails. You can use the same variables
  # as for rejection_reason below.
default[:dovecot][:lda_rejection_subject] = 'Rejected:%s'

  # Human readable error message for rejection mails. You can use variables:

  # UNIX socket path to master authentication server to find users.
default[:dovecot][:lda_auth_socket_path] = '/var/run/dovecot/auth-master'


 Authentication processes


 Executable location
default[:dovecot][:auth_executable] = '/usr/lib/dovecot/dovecot-auth'

 Set max. process size in megabytes.
default[:dovecot][:auth_process_size] = '256'

 Authentication cache size in kilobytes. 0 means it's disabled.
 Note that bsdauth, PAM and vpopmail require cache_key to be set for caching
 to be used.
default[:dovecot][:auth_cache_size] = '0'
 Time to live in seconds for cached data. After this many seconds the cached
 record is no longer used, *except* if the main database lookup returns
 internal failure. We also try to handle password changes automatically:If
 user's previous authentication was successful, but this one wasn't, the
 cache isn't used. For now this works only with plaintext authentication.
default[:dovecot][:auth_cache_ttl] = '3600'
 TTL for negative hits (user not found, password mismatch).
 0 disables caching them completely.
default[:dovecot][:auth_cache_negative_ttl] = '3600'

 Space separated list of realms for SASL authentication mechanisms that need
 them. You can leave it empty if you don't want to support multiple realms.
 Many clients simply use the first one listed here, so keep the default realm
 first.
default[:dovecot][:auth_realms] = ''

 Default realm/domain to use if none was specified. This is used for both
 SASL realms and appending @domain to username in plaintext logins.
default[:dovecot][:auth_default_realm] = ''

 List of allowed characters in username. If the user-given username contains
 a character not listed in here, the login automatically fails. This is just
 an extra check to make sure user can't exploit any potential quote escaping
 vulnerabilities with SQL/LDAP databases. If you want to allow all characters,
 set this value to empty.
default[:dovecot][:auth_username_chars] = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ01234567890.-_@'

 Username character translations before it's looked up from databases. The
 value contains series of from -> to characters. For example "#@/@" means
 that '#' and '/' characters are translated to '@'.
default[:dovecot][:auth_username_translation] = ''

 Username formatting before it's looked up from databases. You can use
 the standard variables here, eg. %Lu would lowercase the username, %n would
 drop away the domain if it was given, or "%n-AT-%d" would change the '@' into
 "-AT-". This translation is done after auth_username_translation changes.
default[:dovecot][:auth_username_format] = ''

 If you want to allow master users to log in by specifying the master
 username within the normal username string (ie. not using SASL mechanism's
 support for it), you can specify the separator character here. The format
 is then <username><separator><master username>. UW-IMAP uses "*" as the
 separator, so that could be a good choice.
default[:dovecot][:auth_master_user_separator] = ''

 Username to use for users logging in with ANONYMOUS SASL mechanism
default[:dovecot][:auth_anonymous_username] = 'anonymous'

 Log unsuccessful authentication attempts and the reasons why they failed.
default[:dovecot][:auth_verbose] = 'no'

 Even more verbose logging for debugging purposes. Shows for example SQL
 queries.
default[:dovecot][:auth_debug] = 'no'

 In case of password mismatches, log the passwords and used scheme so the
 problem can be debugged. Enabling this also enables auth_debug.
default[:dovecot][:auth_debug_passwords] = 'no'

 Maximum number of dovecot-auth worker processes. They're used to execute
 blocking passdb and userdb queries (eg. MySQL and PAM). They're
 automatically created and destroyed as needed.
default[:dovecot][:auth_worker_max_count] = '30'

 Host name to use in GSSAPI principal names. The default is to use the
 name returned by gethostname(). Use "$ALL" to allow all keytab entries.
default[:dovecot][:auth_gssapi_hostname] = ''

 Kerberos keytab to use for the GSSAPI mechanism. Will use the system
 default (usually /etc/krb5.keytab) if not specified.
default[:dovecot][:auth_krb5_keytab] = ''

 Do NTLM and GSS-SPNEGO authentication using Samba's winbind daemon and
 ntlm_auth helper.
 </usr/share/doc/dovecot-common/wiki/Authentication.Mechanisms.Winbind.txt>
default[:dovecot][:auth_use_winbind] = 'no'

 Path for Samba's ntlm_auth helper binary.
default[:dovecot][:auth_winbind_helper_path] = '/usr/bin/ntlm_auth'

 Number of seconds to delay before replying to failed authentications.
default[:dovecot][:auth_failure_delay] = '2'

  # Space separated list of wanted authentication mechanisms:
  #   plain login digest-md5 cram-md5 ntlm rpa apop anonymous gssapi otp skey
  #   gss-spnego
  # NOTE:See also disable_plaintext_auth setting.

  #
  # Password database is used to verify user's password (and nothing more).
  # You can have multiple passdbs and userdbs. This is useful if you want to
  # allow both system users (/etc/passwd) and virtual users to login without
  # duplicating the system users into virtual database.
  #
  # </usr/share/doc/dovecot-common/wiki/PasswordDatabase.txt>
  #
  # of "master users", who can log in as anyone else. Unless you're using PAM,
  # you probably still want the destination user to be looked up from passdb
  # master passdb. </usr/share/doc/dovecot-common/wiki/Authentication.MasterUsers.txt>

  # If the user is found from that database, authentication will fail.
  # The deny passdb should always be specified before others, so it gets
  # checked first. Here's an example:

  # File contains a list of usernames, one per line
default[:dovecot][:auth_passdb_args] = '/etc/dovecot/dovecot.deny'
default[:dovecot][:auth_passdb_deny] = 'yes'

  # PAM authentication. Preferred nowadays by most systems.
  # Note that PAM can only be used to verify if user's password is correct,
  # so it can't be used as userdb. If you don't want to use a separate user
  # database (passwd usually), you can use static userdb.
  # REMEMBER:You'll need /etc/pam.d/dovecot file created for PAM
  # authentication to actually work. </usr/share/doc/dovecot-common/wiki/PasswordDatabase.PAM.txt>
  
    # PAM plugins need this to work, such as pam_mkhomedir.
    #
    # need that. They aren't ever deleted though, so this isn't enabled by
    # default.
    #
    # max_requests specifies how many PAM lookups to do in one process before
    # recreating the process. The default is 100, because many PAM plugins
    # leak memory.
    #
    # cache_key can be used to enable authentication caching for PAM
    # (auth_cache_size also needs to be set). It isn't enabled by default
    # because PAM modules can do all kinds of checks besides checking password,
    # such as checking IP address. Dovecot can't know about these checks
    # without some help. cache_key is simply a list of variables (see
    # /usr/share/doc/dovecot-common/wiki/Variables.txt) which must match
    # for the cached data to be used.
    # Here are some examples:
    #   %u - Username must match. Probably sufficient for most uses.
    #   %u%r - Username and remote IP address must match.
    #   %u%s - Username and service (ie. IMAP, POP3) must match.
    #
    # The service name can contain variables, for example %Ls expands to
    # pop3 or imap.
    #
    # Some examples:
default[:dovecot][:auth_passdb_args] = 'session=yes %Ls'
default[:dovecot][:auth_passdb_args] = 'cache_key=%u dovecot'
default[:dovecot][:auth_passdb_args] = 'dovecot'

  # System users (NSS, /etc/passwd, or similiar)
  # In many systems nowadays this uses Name Service Switch, which is
  # configured in /etc/nsswitch.conf. </usr/share/doc/dovecot-common/wiki/AuthDatabase.Passwd.txt>
default[:dovecot][:passdb_passwd_args] = ''

  # Shadow passwords for system users (NSS, /etc/shadow or similiar).
  # Deprecated by PAM nowadays.
  # </usr/share/doc/dovecot-common/wiki/PasswordDatabase.Shadow.txt>
default[:dovecot][:passdb_shadow_args] = ''

  # PAM-like authentication for OpenBSD.
  # </usr/share/doc/dovecot-common/wiki/PasswordDatabase.BSDAuth.txt>
default[:dovecot][:passdb_bsdauth_args] = ''

  # passwd-like file with specified location
  # </usr/share/doc/dovecot-common/wiki/AuthDatabase.PasswdFile.txt>
  #passdb passwd-file {
    # <Path for passwd-file>
default[:dovecot][:passdb_passwd-file_args] = ''

  # checkpassword executable authentication
  # NOTE:You will probably want to use "userdb prefetch" with this.
  # </usr/share/doc/dovecot-common/wiki/AuthDatabase.CheckPassword.txt>
    # Path for checkpassword binary
default[:dovecot][:passdb_checkpassword_args] = ''

  # SQL database </usr/share/doc/dovecot-common/wiki/AuthDatabase.SQL.txt>
    # Path for SQL configuration file
default[:dovecot][:passdb_sql_args] = '/etc/dovecot/dovecot-sql.conf'

  # LDAP database </usr/share/doc/dovecot-common/wiki/AuthDatabase.LDAP.txt>
default[:dovecot][:passdb_ldap_args] = '/etc/dovecot/dovecot-ldap.conf'

  # vpopmail authentication </usr/share/doc/dovecot-common/wiki/AuthDatabase.VPopMail.txt>
default[:dovecot][:passdb_vpopmail_args] = ''

  #
  # User database specifies where mails are located and what user/group IDs
  # own them. For single-UID configuration use "static".
  #
  # </usr/share/doc/dovecot-common/wiki/UserDatabase.txt>
  #

  # "prefetch" user database means that the passdb already provided the
  # needed information and there's no need to do a separate userdb lookup.
  # This can be made to work with SQL and LDAP databases, see their example
  # configuration files for more information how to do it.
  # </usr/share/doc/dovecot-common/wiki/UserDatabase.Prefetch.txt>

  # System users (NSS, /etc/passwd, or similiar). In many systems nowadays this
  # uses Name Service Switch, which is configured in /etc/nsswitch.conf.
  # </usr/share/doc/dovecot-common/wiki/AuthDatabase.Passwd.txt>
    # process. This setting causes the lookups to be done in auth worker
    # proceses. Useful with remote NSS lookups that may block.
    # NOTE:Be sure to use this setting with nss_ldap or users might get
    # logged in as each others!
default[:dovecot][:userdb_passwd_args] = ''

  # passwd-like file with specified location
  # </usr/share/doc/dovecot-common/wiki/AuthDatabase.PasswdFile.txt>
default[:dovecot][:userdb_passwd-file_args] = ''

  # checkpassword executable user database lookup
  # </usr/share/doc/dovecot-common/wiki/AuthDatabase.CheckPassword.txt>
    # Path for checkpassword binary
default[:dovecot][:userdb_checkpassword_args] = ''

  # static settings generated from template </usr/share/doc/dovecot-common/wiki/UserDatabase.Static.txt>
    # Template for the fields. Can return anything a userdb could normally
    # return. For example:
    #
default[:dovecot][:userdb_static_args] = 'uid=500 gid=500 home=/var/mail/%u'
    #
    # If you use deliver, it needs to look up users only from the userdb. This
    # of course doesn't work with static because there is no list of users.
    # Normally static userdb handles this by doing a passdb lookup. This works
    # with most passdbs, with PAM being the most notable exception. If you do
    # the args in which case the passdb lookup is skipped.
    #
default[:dovecot][:userdb_static_args] = ''

  # SQL database </usr/share/doc/dovecot-common/wiki/AuthDatabase.SQL.txt>
  #userdb sql {
    # Path for SQL configuration file
default[:dovecot][:userdb_sql_args] = '/etc/dovecot/dovecot-sql.conf'

  # LDAP database </usr/share/doc/dovecot-common/wiki/AuthDatabase.LDAP.txt>
    # Path for LDAP configuration file
default[:dovecot][:userdb_ldap_args] = '/etc/dovecot/dovecot-ldap.conf'

  # vpopmail </usr/share/doc/dovecot-common/wiki/AuthDatabase.VPopMail.txt>

  # User to use for the process. This user needs access to only user and
  # password databases, nothing else. Only shadow and pam authentication
  # requires roots, so use something else if possible. Note that passwd
  # authentication with BSDs internally accesses shadow files, which also
  # requires roots. Note that this user is NOT used to access mails.
  # That user is specified by userdb above.

  # Directory where to chroot the process. Most authentication backends don't
  # work if this is set, and there's no point chrooting if auth_user is root.
  # Note that valid_chroot_dirs isn't needed to use this setting.
default[:dovecot][:chroot] = ''

  # Number of authentication processes to create
default[:dovecot][:count] = '1'

  # Require a valid SSL client certificate or the authentication fails.
default[:dovecot][:ssl_require_client_cert] = 'no'

  # Take the username from client's SSL certificate, using
  # X509_NAME_get_text_by_NID() which returns the subject's DN's
  # CommonName.
default[:dovecot][:ssl_username_from_cert] = 'no'

  # It's possible to export the authentication interface to other programs:
      # Master socket provides access to userdb information. It's typically
      # used to give Dovecot's local delivery agent access to userdb so it
      # can find mailbox locations.
default[:dovecot][:socket_listen_master_path] = 'path/var/run/dovecot/auth-master'
default[:dovecot][:socket_listen_master_mode] = '0600'
      # Default user/group is the one who started dovecot-auth (root)
default[:dovecot][:socket_listen_master_user] = ''
default[:dovecot][:socket_listen_master_group] = ''
      # The client socket is generally safe to export to everyone. Typical use
      # is to export it to your SMTP server so it can do SMTP AUTH lookups
      # using it.
default[:dovecot][:socket_listen_client_path] = 'path/var/run/dovecot/auth-client'
default[:dovecot][:socket_listen_client_mode] = '0660'

 If you wish to use another authentication server than dovecot-auth, you can
 use connect sockets. They are assumed to be already running, Dovecot's master
 process only tries to connect to them. They don't need any other settings
 than the path for the master socket, as the configuration is done elsewhere.
 Note that the client sockets must exist in the login_dir.
default[:dovecot][:auth_external_socket_connect_masterpath] = '/var/run/dovecot/auth-master'


 Dictionary server settings


 quota, expire and acl plugins. The dictionary can be used either directly or
 though a dictionary server. The following dict block maps dictionary names to
 URIs when the server is used. These can then be referenced using URIs in
 format "proxy::<name>".

default[:dovecot][:dict_quota] = 'mysql:/etc/dovecot/dovecot-dict-quota.conf'
default[:dovecot][:dict_expire] = 'db:/var/lib/dovecot/expire.db'

 Path to Berkeley DB's configuration file. See doc/dovecot-db-example.conf
default[:dovecot][:dict_db_config] = ''


 Plugin settings


  # Here you can give some extra environment variables to mail processes.
  # This is mostly meant for passing parameters to plugins. %variable
  # expansion is done for all values.

  # Quota plugin. Multiple backends are supported:
  #   dirsize:Find and sum all the files found from mail directory.
  #            Extremely SLOW with Maildir. It'll eat your CPU and disk I/O.
  #   dict:Keep quota stored in dictionary (eg. SQL)
  #   maildir:Maildir++ quota
  #   fs:Read-only support for filesystem quota
  #
  # Quota limits are set using "quota_rule" parameters, either in here or in
  # userdb. It's also possible to give mailbox-specific limits, for example:
  # User has now 1GB quota, but when saving to Trash mailbox the user gets
  # additional 100MB.
  #
  # Multiple quota roots are also possible, for example:
  # Gives each user their own 100MB quota and one shared 1GB quota within
  # the domain.
  #
  # You can execute a given command when user exceeds a specified quota limit.
  # Each quota root has separate limits. Only the command for the first
  # exceeded limit is excecuted, so put the highest limit first.
  # Note that % needs to be escaped as %%, otherwise "% " expands to empty.
default[:dovecot][:plugin_quota_warning] = 'storage=95%% /usr/local/bin/quota-warning.sh 95'
default[:dovecot][:plugin_quota_warning2] = 'storage=80%% /usr/local/bin/quota-warning.sh 80'
default[:dovecot][:plugin_quota] = 'maildir'

  # ACL plugin. vfile backend reads ACLs from "dovecot-acl" file from maildir
  # directory. You can also optionally give a global ACL directory path where
  # ACLs are applied to all users' mailboxes. The global ACL directory contains
  # one file for each mailbox, eg. INBOX or sub.mailbox. cache_secs parameter
  # specifies how many seconds to wait between stat()ing dovecot-acl file
  # to see if it changed.
default[:dovecot][:acl] = 'vfile:/etc/dovecot/dovecot-acls:cache_secs=300'

  # To let users LIST mailboxes shared by other users, Dovecot needs a
  # shared mailbox dictionary. For example:
default[:dovecot][:acl_shared_dict] = 'file:/var/lib/dovecot/shared-mailboxes'

  # Convert plugin. If set, specifies the source storage path which is
  # converted to destination storage (mail_location) when the user logs in.
  # The existing mail directory is renamed to <dir>-converted.
default[:dovecot][:convert_mail] = 'mbox:%h/mail'
  # Skip mailboxes which we can't open successfully instead of aborting.
default[:dovecot][:convert_skip_broken_mailboxes] = 'no'
  # Skip directories beginning with '.'
default[:dovecot][:convert_skip_dotdirs] = 'no'
  # If source storage has mailbox names with destination storage's hierarchy
  # separators, replace them with this character.
default[:dovecot][:convert_alt_hierarchy_char] = '_'

  # Trash plugin. When saving a message would make user go over quota, this
  # plugin automatically deletes the oldest mails from configured mailboxes
  # until the message can be saved within quota limits. The configuration file
  # is a text file where each line is in format:<priority> <mailbox name>
  # Mails are first deleted in lowest -> highest priority number order
default[:dovecot][:trash] = '/etc/dovecot/dovecot-trash.conf'

  # Expire plugin. Mails are expunged from mailboxes after being there the
  # configurable time. The first expiration date for each mailbox is stored in
  # a dictionary so it can be quickly determined which mailboxes contain
  # expired mails. The actual expunging is done in a nightly cronjob, which
  # you must set up:
  #   dovecot --exec-mail ext /usr/lib/dovecot/expire-tool.sh
default[:dovecot][:expire] = 'Trash 7 Spam 30'
default[:dovecot][:expire_dict] = 'proxy::expire'

  # Lazy expunge plugin. Currently works only with maildirs. When a user
  # expunges mails, the mails are moved to a mailbox in another namespace
  # (1st). When a mailbox is deleted, the mailbox is moved to another namespace
  # (2nd) as well. Also if the deleted mailbox had any expunged messages,
  # they're moved to a 3rd namespace. The mails won't be counted in quota,
  # and they're not deleted automatically (use a cronjob or something).
default[:dovecot][:lazy_expunge] = '.EXPUNGED/ .DELETED/ .DELETED/.EXPUNGED/'

  # Events to log. Also available:flag_change append
default[:dovecot][:mail_log_events] = 'delete undelete expunge copy mailbox_delete mailbox_rename'
  # Group events within a transaction to one line.
default[:dovecot][:mail_log_group_events] = 'no'
  # Available fields:uid, box, msgid, from, subject, size, vsize, flags
  # size and vsize are available only for expunge and copy events.
default[:dovecot][:mail_log_fields] = 'uid box msgid size'

  # Sieve plugin (http://wiki.dovecot.org/LDA/Sieve) and ManageSieve service
  #
  # Location of the active script. When ManageSieve is used this is actually
  # a symlink pointing to the active script in the sieve storage directory.
default[:dovecot][:sieve] = 'dovecot.sieve'
  #
  # The path to the directory where the personal Sieve scripts are stored. For
  # ManageSieve this is where the uploaded scripts are stored.
default[:dovecot][:sieve_dir] = 'sieve'

 Config files can also be included. deliver doesn't support them currently.
 Optional configurations, don't give an error if it's not found:
default[:dovecot][:includes] = ['/etc/dovecot/conf.d/*.conf','/etc/dovecot/extra.conf ']

 DB Settings
 Example DB_CONFIG for Berkeley DB. Typically dict_db_config setting is used
 to point to this file.
 http://www.oracle.com/technology/documentation/berkeley-db/db/ref/env/db_config.html

 Maximum number of simultaneous transactions.
 
default[:dovecot][:set_tx_max] = '1000'

 http://www.oracle.com/technology/documentation/berkeley-db/db/ref/lock/max.html
default[:dovecot][:set_lk_max_locks ] = '1000'
default[:dovecot][:set_lk_max_lockers ] = '1000'
default[:dovecot][:set_lk_max_objects ] = '1000'

 SQL Dict example settings
default[:dovecot][:host] = 'localhost'
default[:dovecot][:dbname] = 'mails'
default[:dovecot][:user] = 'testuser'
default[:dovecot][:password] = 'pass'

default[:dovecot][:pattern] = 'priv/quota/storage'
default[:dovecot][:table] = 'quota'
default[:dovecot][:username_field] = 'username'
default[:dovecot][:mailbox_field] = '$mailbox'
default[:dovecot][:value_field] = 'bytes'

 LDAP Settings
 This file is opened as root, so it should be owned by root and mode 0600.

 http://wiki.dovecot.org/AuthDatabase/LDAP

 NOTE:If you're not using authentication binds, you'll need to give
 dovecot-auth read access to userPassword field in the LDAP server.
 With OpenLDAP this is done by modifying /etc/ldap/slapd.conf. There should
 already be something like this:

 access to attribute=userPassword
        by dn="<dovecot's dn>" read # add this
        by anonymous auth
        by self write
        by * none

 Space separated list of LDAP hosts to use. host:port is allowed too.
default[:dovecot][:hosts] = ''

 LDAP URIs to use. You can use this instead of hosts list. Note that this
 setting isn't supported by all LDAP libraries.
default[:dovecot][:] = ''

 Distinguished Name - the username used to login to the LDAP server.
 Leave it commented out to bind anonymously (useful with auth_bind=yes).
default[:dovecot][:dn] = 'yes'

 Password for LDAP server, if dn is specified.
default[:dovecot][:dnpass] = ''

 Use SASL binding instead of the simple binding. Note that this changes
 ldap_version automatically to be 3 if it's lower. Also note that SASL binds
 and auth_bind=yes don't work together.
default[:dovecot][:sasl_bind] = 'no'
 SASL mechanism name to use.
default[:dovecot][:sasl_mech] = ''
 SASL realm to use#.
default[:dovecot][:sasl_realm] = ''
 SASL authorization ID, ie. the dnpass is for this "master user", but th#default[:dovecot][:sasl_realm] = ''e
 dn is still the logged in user. Normally you want to keep this empty.
default[:dovecot][:sasl_authz_id] = ''

 Use TLS to connect to the LDAP server.
default[:dovecot][:tls] = 'no'
 TLS options, currently supported only with OpenLDAP:
default[:dovecot][:tls_ca_cert_file] = ''

default[:dovecot][:tls_ca_cert_dir] = ''

default[:dovecot][:tls_cert_file] = ''

default[:dovecot][:tls_key_file] = ''

default[:dovecot][:tls_cipher_suite] = ''
 Valid values: never, hard, demand, allow, try
default[:dovecot][:tls_require_cert] = ''

 Use the given ldaprc path.
default[:dovecot][:ldaprc_path] = ''

 LDAP library debug level as specified by LDAP_DEBUG_* in ldap_log.h.
 -1 = everything. You may need to recompile OpenLDAP with debugging enabled
 to get enough output.
default[:dovecot][:debug_level] = '0'

 Use authentication binding for verifying password's validity. This works by
 logging into LDAP server using the username and password given by client.
 The pass_filter is used to find the DN for the user. Note that the pass_attrs
 is still used, only the password field is ignored in it. Before doing any
 search, the binding is switched back to the default DN.
default[:dovecot][:auth_bind] = 'no'

 If authentication binding is used, you can save one LDAP request per login
 if users' DN can be specified with a common template. The template can use
 the standard %variables (see user_filter). Note that you can't
 use any pass_attrs if you use this setting.

 If you use this setting, it's a good idea to use a different
 dovecot-ldap.conf for userdb (it can even be a symlink, just as long as the
 filename is different in userdb's args). That way one connection is used only
 for LDAP binds and another connection is used for user lookups. Otherwise
 the binding is changed to the default DN before each user lookup.

 For example:
   auth_bind_userdn = cn=%u,ou=people,o=org

default[:dovecot][:auth_bind_userdn] = ''

 LDAP protocol version to use. Likely 2 or 3.
default[:dovecot][:ldap_version] = '3'

 LDAP base. %variables can be used here.
 For example:dc=mail, dc=example, dc=org

 Dereference:never, searching, finding, always
default[:dovecot][:deref] = 'never'

 Search scope:base, onelevel, subtree
default[:dovecot][:scope] = 'subtree'

 User attributes are given in LDAP-name=dovecot-internal-name list. The
 internal names are:
   uid - System UID
   gid - System GID
   home - Home directory
   mail - Mail location

 There are also other special fields which can be returned, see
 http://wiki.dovecot.org/UserDatabase/ExtraFields
default[:dovecot][:user_attrs] = 'homeDirectory=home,uidNumber=uid,gidNumber=gid'

 Filter for user lookup. Some variables can be used (see
 http://wiki.dovecot.org/Variables for full list):
   %u - username
   %n - user part in user@domain, same as %u if there's no domain
   %d - domain part in user@domain, empty if user there's no domain
default[:dovecot][:user_filter] = '(&(objectClass=posixAccount)(uid=%u))'

 Password checking attributes:
  user:Virtual user name (user@domain), if you wish to change the
        user-given username to something else
  password:Password, may optionally start with {type}, eg. {crypt}
 There are also other special fields which can be returned, see
 http://wiki.dovecot.org/PasswordDatabase/ExtraFields
default[:dovecot][:pass_attrs] = 'uid=user,userPassword=password'

 If you wish to avoid two LDAP lookups (passdb + userdb), you can use
 userdb prefetch instead of userdb ldap in dovecot.conf. In that case you'll
 also have to include user_attrs in pass_attrs field prefixed with "userdb_"
 string. For example:
default[:dovecot][:pass_attrs] = 'uid=user,userPassword=password,\'
default[:dovecot][:homeDirectory] = 'userdb_home,uidNumber=userdb_uid,gidNumber=userdb_gid'

 Filter for password lookups
default[:dovecot][:pass_filter] = '(&(objectClass=posixAccount)(uid=%u))'

 Default password scheme. "{scheme}" before password overrides this.
 List of supported schemes is in:http://wiki.dovecot.org/Authentication
default[:dovecot][:default_pass_scheme] = 'CRYPT'


 Dovecot-SQL
 http://wiki.dovecot.org/AuthDatabase/SQL

 For the sql passdb module, you'll need a database with a table that
 contains fields for at least the username and password. If you want to
 use the user@domain syntax, you might want to have a separate domain
 field as well.

 If your users all have the same uig/gid, and have predictable home
 directories, you can use the static userdb module to generate the home
 dir based on the username and domain. In this case, you won't need fields
 for home, uid, or gid in the database.

 If you prefer to use the sql userdb module, you'll want to add fields
 for home, uid, and gid. Here is an example table:

 CREATE TABLE users (
     username VARCHAR(128) NOT NULL,
     domain VARCHAR(128) NOT NULL,
     password VARCHAR(64) NOT NULL,
     home VARCHAR(255) NOT NULL,
     uid INTEGER NOT NULL,
     gid INTEGER NOT NULL,
     active CHAR(1) DEFAULT 'Y' NOT NULL
 );

 Database driver: mysql, pgsql, sqlite
default[:dovecot][:driver] = ''

 Database connection string. This is driver-specific setting.

 pgsql:
   For available options, see the PostgreSQL documention for the
   PQconnectdb function of libpq.

 mysql:
   Basic options emulate PostgreSQL option names:
     host, port, user, password, dbname

   But also adds some new settings:
     client_flags        - See MySQL manual
     ssl_ca, ssl_ca_path - Set either one or both to enable SSL
     ssl_cert, ssl_key   - For sending client-side certificates to server
     ssl_cipher          - Set minimum allowed cipher security (default: HIGH)
     option_file         - Read options from the given file instead of
                           the default my.cnf location
     option_group        - Read options from the given group (default: client)
 
   You can connect to UNIX sockets by using host: host=/var/run/mysqld/mysqld.sock
   Note that currently you can't use spaces in parameters.

   MySQL supports multiple host parameters for load balancing / HA.

 sqlite:
   The path to the database file.

 Examples:
   connect = host=192.168.1.1 dbname=users
   connect = host=sql.example.com dbname=virtual user=virtual password=blarg
   connect = /etc/dovecot/authdb.sqlite

default[:dovecot][:connect] = ''

 Default password scheme.

 List of supported schemes is in
 http://wiki.dovecot.org/Authentication/PasswordSchemes

default[:dovecot][:default_pass_scheme] = 'MD5'

 passdb query to retrieve the password. It can return fields:
   password - The user's password. This field must be returned.
   user - user@domain from the database. Needed with case-insensitive lookups.
   username and domain - An alternative way to represent the "user" field.

 The "user" field is often necessary with case-insensitive lookups to avoid
 e.g. "name" and "nAme" logins creating two different mail directories. If
 your user and domain names are in separate fields, you can return "username"
 and "domain" fields instead of "user".

 The query can also return other fields which have a special meaning, see
 http://wiki.dovecot.org/PasswordDatabase/ExtraFields

 Commonly used available substitutions (see http://wiki.dovecot.org/Variables
 for full list):
   %u = entire user@domain
   %n = user part of user@domain
   %d = domain part of user@domain
 
 Note that these can be used only as input to SQL query. If the query outputs
 any of these substitutions, they're not touched. Otherwise it would be
 difficult to have eg. usernames containing '%' characters.

 Example:
   password_query = SELECT userid AS user, pw AS password \
     FROM users WHERE userid = '%u' AND active = 'Y'

default[:dovecot][:password_query] = 'SELECT username, domain, password '
default[:dovecot][:password_query] <<  "FROM users WHERE username = '%n' AND domain = '%d'"

 userdb query to retrieve the user information. It can return fields:
   uid - System UID (overrides mail_uid setting)
   gid - System GID (overrides mail_gid setting)
   home - Home directory
   mail - Mail location (overrides mail_location setting)

 None of these are strictly required. If you use a single UID and GID, and
 home or mail directory fits to a template string, you could use userdb static
 instead. For a list of all fields that can be returned, see
 http://wiki.dovecot.org/UserDatabase/ExtraFields

Examples:
 user_query = SELECT home, uid, gid FROM users WHERE userid = '%u'
 user_query = SELECT dir AS home, user AS uid, group AS gid FROM users where userid = '%u'
 user_query = SELECT home, 501 AS uid, 501 AS gid FROM users WHERE userid = '%u'

default[:dovecot][:user_query] = 'SELECT home, uid, gid '
default[:dovecot][:user_query] << "FROM users WHERE username = '%n' AND domain = '%d'"

If you wish to avoid two SQL lookups (passdb + userdb), you can use
userdb prefetch instead of userdb sql in dovecot.conf. In that case you'll
also have to return userdb fields in password_query prefixed with "userdb_"
string. For example:
default[:dovecot][:password_query] = 'SELECT userid AS user, password, '
default[:dovecot][:password_query] << 'home AS userdb_home, uid AS userdb_uid, gid AS userdb_gid '
default[:dovecot][:password_query] << 'FROM users WHERE userid = '%u''



Usage
=====


Examples
=====

