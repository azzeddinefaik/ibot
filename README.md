Usage:
    foreman-installer [OPTIONS]

Options:

= Generic:
    --reset                       This option will drop the Katello database and clear all subsequent backend data stores.You will lose all data! Unfortunately we
                                  can't detect a failure at the moment so you should verify the success
                                  manually. e.g. dropping can fail when DB is currently in use. (default: false)
    --clear-pulp-content          This option will clear all Pulp content from disk located in '/var/lib/pulp/content/'. (default: false)
    --clear-puppet-environments   This option will clear all published Puppet environments from disk. (default: false)
    --disable-system-checks       This option will skip the system checks for memory. (default: false)
    --force-upgrade-steps         This option will force upgrade steps to run that are normally only run once. (default: false)
    --certs-update-server         This option will enforce an update of the HTTPS certificates (default: false)
    --certs-update-server-ca      This option will enforce an update of the CA used for HTTPS certificates. (default: false)
    --certs-update-all            This option will enforce an update of all the certificates for given host (default: false)
    --certs-skip-check            This option will cause skipping the certificates sanity check. Use with caution (default: false)
    --upgrade                     Run the steps neccessary for an upgrade such as migrations, rake tasks, etc. (default: false)
    --upgrade-puppet              Run the steps neccessary to upgrade from Puppet 3 to Puppet 4. (default: false)
    --[no-]colors                 Use color output on STDOUT (default: true)
    --color-of-background COLOR   Your terminal background is :bright or :dark (default: :dark)
    -d, --dont-save-answers       Skip saving answers to '/etc/foreman-installer/scenarios.d/katello-answers.yaml'? (default: false)
    --ignore-undocumented         Ignore inconsistent parameter documentation (default: false)
    -i, --interactive             Run in interactive mode
    --log-level LEVEL             Log level for log file output (default: "DEBUG")
    -n, --noop                    Run puppet in noop mode? (default: false)
    -p, --profile                 Run puppet in profile mode? (default: false)
    -s, --skip-checks-i-know-better Skip all system checks (default: false)
    -v, --verbose                 Display log on STDOUT instead of progressbar
    -l, --verbose-log-level LEVEL Log level for verbose mode output (default: "info")
    -S, --scenario SCENARIO       Use installation scenario
    --disable-scenario SCENARIO   Disable installation scenario
    --enable-scenario SCENARIO    Enable installation scenario
    --list-scenarios              List available installation scenaraios
    --force                       Force change of installation scenaraio
    --compare-scenarios           Show changes between last used scenario and the scenario specified with -S or --scenario argument
    --migrations-only             Apply migrations to a selected scenario and exit
    -h, --help                    print help
    --full-help                   print complete help
    --[no-]enable-capsule         Enable 'capsule' puppet module (default: true)
    --[no-]enable-certs           Enable 'certs' puppet module (default: true)
    --[no-]enable-foreman         Enable 'foreman' puppet module (default: true)
    --[no-]enable-foreman-plugin-bootdisk Enable 'foreman_plugin_bootdisk' puppet module (default: false)
    --[no-]enable-foreman-plugin-chef Enable 'foreman_plugin_chef' puppet module (default: false)
    --[no-]enable-foreman-plugin-default-hostgroup Enable 'foreman_plugin_default_hostgroup' puppet module (default: false)
    --[no-]enable-foreman-plugin-discovery Enable 'foreman_plugin_discovery' puppet module (default: false)
    --[no-]enable-foreman-plugin-hooks Enable 'foreman_plugin_hooks' puppet module (default: false)
    --[no-]enable-foreman-plugin-openscap Enable 'foreman_plugin_openscap' puppet module (default: false)
    --[no-]enable-foreman-plugin-puppetdb Enable 'foreman_plugin_puppetdb' puppet module (default: false)
    --[no-]enable-foreman-plugin-remote-execution Enable 'foreman_plugin_remote_execution' puppet module (default: false)
    --[no-]enable-foreman-plugin-setup Enable 'foreman_plugin_setup' puppet module (default: false)
    --[no-]enable-foreman-plugin-tasks Enable 'foreman_plugin_tasks' puppet module (default: true)
    --[no-]enable-foreman-plugin-templates Enable 'foreman_plugin_templates' puppet module (default: false)
    --[no-]enable-foreman-proxy   Enable 'foreman_proxy' puppet module (default: true)
    --[no-]enable-foreman-proxy-plugin-openscap Enable 'foreman_proxy_plugin_openscap' puppet module (default: false)
    --[no-]enable-foreman-proxy-plugin-pulp Enable 'foreman_proxy_plugin_pulp' puppet module (default: true)
    --[no-]enable-foreman-proxy-plugin-remote-execution-ssh Enable 'foreman_proxy_plugin_remote_execution_ssh' puppet module (default: false)
    --[no-]enable-katello         Enable 'katello' puppet module (default: true)


= Module capsule:
    --capsule-certs-tar           Path to a tar with certs for the node (default: nil)
    --capsule-enable-ostree       Boolean to enable ostree plugin. This requires existence of an ostree install. (default: false)
    --capsule-parent-fqdn         FQDN of the parent node. (default: "katello.localdomain")
    --capsule-puppet              Use puppet (default: true)
    --capsule-puppet-ca-proxy     The actual server that handles puppet CA.
                                  Setting this to anything non-empty causes
                                  the apache vhost to set up a proxy for all
                                  certificates pointing to the value. (default: nil)
    --capsule-puppet-server-implementation  Puppet master implementation, either "master" (traditional
                                  Ruby) or "puppetserver" (JVM-based) (default: nil)


= Module certs:
    --certs-node-fqdn             The fqdn of the host the generated certificates
                                  should be for (default: "katello.localdomain")
    --certs-server-ca-cert        Path to the CA that issued the ssl certificates for https
                                  if not specified, the default CA will be used (default: nil)
    --certs-server-cert           Path to the ssl certificate for https
                                  if not specified, the default CA will generate one (default: nil)
    --certs-server-cert-req       Path to the ssl certificate request for https
                                  if not specified, the default CA will generate one (default: nil)
    --certs-server-key            Path to the ssl key for https
                                  if not specified, the default CA will generate one (default: nil)


= Module foreman:
    --foreman-admin-email         E-mail address of the initial admin user (default: nil)
    --foreman-admin-first-name    First name of the initial admin user (default: nil)
    --foreman-admin-last-name     Last name of the initial admin user (default: nil)
    --foreman-admin-password      Password of the initial admin user, default is randomly generated (default: "3K3cUXYrqEVAHQNN")
    --foreman-admin-username      Username for the initial admin user (default: "admin")
    --foreman-app-root            Name of foreman root directory (default: "/usr/share/foreman")
    --foreman-authentication      Enable user authentication. Initial credentials are set using admin_username
                                  and admin_password. (default: true)
    --foreman-client-ssl-ca       Defines the SSL CA used to communicate with Foreman Proxies (default: "/etc/foreman/proxy_ca.pem")
    --foreman-client-ssl-cert     Defines the SSL certificate used to communicate with Foreman Proxies (default: "/etc/foreman/client_cert.pem")
    --foreman-client-ssl-key      Defines the SSL private key used to communicate with Foreman Proxies (default: "/etc/foreman/client_key.pem")
    --foreman-configure-epel-repo  If disabled the EPEL repo will not be configured on Red Hat family systems. (default: false)
    --foreman-configure-scl-repo  If disabled the SCL repo will not be configured on Red Hat clone systems.
                                  (Currently only installs repos for CentOS and Scientific) (default: false)
    --foreman-custom-repo         No need to change anything here by default
                                  if set to true, no repo will be added by this module, letting you to
                                  set it to some custom location. (default: true)
    --foreman-db-adapter          Database 'production' adapter (default: nil)
    --foreman-db-database         Database 'production' database (e.g. foreman) (default: nil)
    --foreman-db-host             Database 'production' host (default: nil)
    --foreman-db-manage           if enabled, will install and configure the database server on this host (default: true)
    --foreman-db-password         Database 'production' password (default is random) (default: "9x9CsGPuuwSsPFZbURKRSCGPoiVfneJN")
    --foreman-db-pool             Database 'production' size of connection pool (default: 5)
    --foreman-db-port             Database 'production' port (default: nil)
    --foreman-db-sslmode          Database 'production' ssl mode (default: nil)
    --foreman-db-type             Database 'production' type (valid types: mysql/postgresql/sqlite) (default: "postgresql")
    --foreman-db-username         Database 'production' user (e.g. foreman) (default: "foreman")
    --foreman-email-conf          email configuration file, defaults to /etc/foreman/email.yaml (default: "email.yaml")
    --foreman-email-delivery-method  can be sendmail or smtp regarding to foreman documentation (default: nil)
    --foreman-email-smtp-address  if delivery_method is smtp, this should contain an valid smtp host (default: nil)
    --foreman-email-smtp-authentication  authentication settings, can be none or login, defaults to none (default: "none")
    --foreman-email-smtp-domain   email domain (default: nil)
    --foreman-email-smtp-password  password for mail server auth, if authentication login (default: nil)
    --foreman-email-smtp-port     smtp port, defaults to 25 (default: "25")
    --foreman-email-smtp-user-name  user_name for mail server auth, if authentication login (default: nil)
    --foreman-email-source        template to use for email configuration file (default: "email.yaml.erb")
    --foreman-foreman-url         URL on which foreman is going to run (default: "https://katello.localdomain")
    --foreman-gpgcheck            turn on/off gpg check in repo files (effective only on RedHat family systems) (default: true)
    --foreman-group               Primary group for the Foreman user (default: "foreman")
    --foreman-http-keytab         Path to keytab to be used for Kerberos authentication on the WebUI (default: "/etc/httpd/conf/http.keytab")
    --foreman-initial-location    Name of an initial location (default: "Default Location")
    --foreman-initial-organization  Name of an initial organization (default: "Default Organization")
    --foreman-ipa-authentication  Enable configuration for external authentication via IPA (default: false)
    --foreman-ipa-manage-sssd     If ipa_authentication is true, should the installer manage SSSD? You can disable it
                                  if you use another module for SSSD configuration (default: true)
    --foreman-keepalive           Enable KeepAlive setting of Apache? (default: true)
    --foreman-keepalive-timeout   KeepAliveTimeout setting of Apache
                                  (Seconds the server will wait for subsequent requests on a persistent connection) (default: 5)
    --foreman-locations-enabled   Enable locations? (default: true)
    --foreman-loggers             Enable or disable specific loggers, e.g. {"sql" => true} (default: {})
    --foreman-logging-level       Logging level of the Foreman application (valid values: debug, info, warn, error, fatal) (default: "info")
    --foreman-manage-user         Controls whether foreman module will manage the user on the system. (default true) (default: true)
    --foreman-max-keepalive-requests  MaxKeepAliveRequests setting of Apache
                                  (Number of requests allowed on a persistent connection) (default: 100)
    --foreman-oauth-active        Enable OAuth authentication for REST API (default: true)
    --foreman-oauth-consumer-key  OAuth consumer key (default: "WRDZ2HMe5HwBfMiuyzmPk6fGpqSyyHfy")
    --foreman-oauth-consumer-secret  OAuth consumer secret (default: "J7qZFopiMhiR2XETdP4PbAr4FJT8kCkE")
    --foreman-oauth-map-users     Should foreman use the foreman_user header to identify API user? (default: false)
    --foreman-organizations-enabled  Enable organizations? (default: true)
    --foreman-pam-service         PAM service used for host-based access control in IPA (default: "foreman")
    --foreman-passenger           Configure foreman via apache and passenger (default: true)
    --foreman-passenger-interface  Defines which network interface passenger should listen on, undef means all interfaces (default: nil)
    --foreman-passenger-min-instances  Minimum passenger worker instances to keep when application is idle. (default: 1)
    --foreman-passenger-prestart  Pre-start the first passenger worker instance process during httpd start. (default: true)
    --foreman-passenger-ruby      Ruby interpreter used to run Foreman under Passenger (default: "/usr/bin/tfm-ruby")
    --foreman-passenger-ruby-package  Package to install to provide Passenger libraries for the active Ruby
                                  interpreter (default: "tfm-rubygem-passenger-native")
    --foreman-passenger-start-timeout  Amount of seconds to wait for Ruby application boot. (default: 600)
    --foreman-plugin-prefix       String which is prepended to the plugin package names (default: "tfm-rubygem-foreman_")
    --foreman-plugin-version      foreman plugins package version, it's passed to ensure parameter of package resource
                                  can be set to 'installed', 'latest', 'present' only (default: "present")
    --foreman-puppet-home         Puppet home directory (default: "/var/lib/puppet")
    --foreman-puppet-ssldir       Puppet SSL directory (default: "/etc/puppetlabs/puppet/ssl")
    --foreman-puppetrun           Should foreman be able to start puppetruns on nodes (default: false)
    --foreman-rails-env           Rails environment of foreman (default: "production")
    --foreman-repo                This can be stable, nightly or a specific version i.e. 1.7 (default: "stable")
    --foreman-selinux             when undef, foreman-selinux will be installed if SELinux is enabled
                                  setting to false/true will override this check (e.g. set to false on 1.1) (default: nil)
    --foreman-server-port         Defines Apache port for HTTP requests (default: 80)
    --foreman-server-ssl-ca       Defines Apache mod_ssl SSLCACertificateFile setting in Foreman vhost conf file. (default: "/etc/pki/katello/certs/katello-default-ca.crt")
    --foreman-server-ssl-cert     Defines Apache mod_ssl SSLCertificateFile setting in Foreman vhost conf file. (default: "/etc/pki/katello/certs/katello-apache.crt")
    --foreman-server-ssl-certs-dir  Defines Apache mod_ssl SSLCACertificatePath setting in Foreman vhost conf file. (default: "")
    --foreman-server-ssl-chain    Defines Apache mod_ssl SSLCertificateChainFile setting in Foreman vhost conf file. (default: "/etc/pki/katello/certs/katello-server-ca.crt")
    --foreman-server-ssl-crl      Defines the Apache mod_ssl SSLCARevocationFile setting in Foreman vhost conf file. (default: false)
    --foreman-server-ssl-key      Defines Apache mod_ssl SSLCertificateKeyFile setting in Foreman vhost conf file. (default: "/etc/pki/katello/private/katello-apache.key")
    --foreman-server-ssl-port     Defines Apache port for HTTPS reqquests (default: 443)
    --foreman-serveraliases       Server aliases of the VirtualHost in the webserver (default: ["foreman"])
    --foreman-servername          Server name of the VirtualHost in the webserver (default: "katello.localdomain")
    --foreman-ssl                 Enable and set require_ssl in Foreman settings (note: requires passenger, SSL does not apply to kickstarts) (default: true)
    --foreman-unattended          Should foreman manage host provisioning as well (default: true)
    --foreman-use-vhost           Enclose apache configuration in VirtualHost tags (default: true)
    --foreman-user                User under which foreman will run (default: "foreman")
    --foreman-user-groups         Additional groups for the Foreman user (default: ["puppet"])
    --foreman-version             foreman package version, it's passed to ensure parameter of package resource
                                  can be set to specific version number, 'latest', 'present' etc. (default: "present")
    --foreman-vhost-priority      Defines Apache vhost priority for the Foreman vhost conf file. (default: "05")
    --foreman-websockets-encrypt  Whether to encrypt websocket connections (default: true)
    --foreman-websockets-ssl-cert  SSL certificate file to use when encrypting websocket connections (default: "/etc/pki/katello/certs/katello-apache.crt")
    --foreman-websockets-ssl-key  SSL key file to use when encrypting websocket connections (default: "/etc/pki/katello/private/katello-apache.key")


= Module foreman_plugin_discovery:
    --foreman-plugin-discovery-image-name  tarball with images (default: "fdi-image-latest.tar")
    --foreman-plugin-discovery-install-images  should the installer download and setup discovery images
                                  for you? the average size is few hundreds of MB (default: false)
    --foreman-plugin-discovery-source-url  source URL to download from (default: "http://downloads.theforeman.org/discovery/releases/latest/")
    --foreman-plugin-discovery-tftp-root  tftp root to install image into (default: "/var/lib/tftpboot")


= Module foreman_plugin_puppetdb:
    --foreman-plugin-puppetdb-address  Address of puppetdb API. Defaults to 'https://localhost:8081/v2/commands' (default: "https://localhost:8081/v2/commands")
    --foreman-plugin-puppetdb-dashboard-address  Address of puppetdb dashboard. Defaults to 'http://localhost:8080/dashboard' (default: "http://localhost:8080/dashboard")
    --foreman-plugin-puppetdb-package  Package name to install, use ruby193-rubygem-puppetdb_foreman on Foreman 1.8/1.9 on EL (default: "tfm-rubygem-puppetdb_foreman")


= Module foreman_plugin_tasks:
    --foreman-plugin-tasks-package  Package name to install, use ruby193-rubygem-foreman-tasks on Foreman 1.8/1.9 on EL (default: "tfm-rubygem-foreman-tasks")
    --foreman-plugin-tasks-service  Service name (default: "foreman-tasks")


= Module foreman_proxy:
    --foreman-proxy-bind-host     Host to bind ports to, e.g. *, localhost, 0.0.0.0 (default: "*")
    --foreman-proxy-bmc           Enable BMC feature (default: false)
    --foreman-proxy-bmc-default-provider  BMC default provider. (default: "ipmitool")
    --foreman-proxy-bmc-listen-on  BMC proxy to listen on https, http, or both (default: "https")
    --foreman-proxy-custom-repo   No need to change anything here by default
                                  if set to true, no repo will be added by this module, letting you to
                                  set it to some custom location. (default: true)
    --foreman-proxy-customrun-args  Puppet customrun command arguments (default: "-ay -f -s")
    --foreman-proxy-customrun-cmd  Puppet customrun command (default: "/bin/false")
    --foreman-proxy-dhcp          Enable DHCP feature (default: false)
    --foreman-proxy-dhcp-config   DHCP config file path (default: "/etc/dhcp/dhcpd.conf")
    --foreman-proxy-dhcp-gateway  DHCP pool gateway (default: "192.168.100.1")
    --foreman-proxy-dhcp-interface  DHCP listen interface (default: "eth0")
    --foreman-proxy-dhcp-key-name  DHCP key name (default: nil)
    --foreman-proxy-dhcp-key-secret  DHCP password (default: nil)
    --foreman-proxy-dhcp-leases   DHCP leases file (default: "/var/lib/dhcpd/dhcpd.leases")
    --foreman-proxy-dhcp-listen-on  DHCP proxy to listen on https, http, or both (default: "https")
    --foreman-proxy-dhcp-managed  DHCP is managed by Foreman proxy (default: true)
    --foreman-proxy-dhcp-nameservers  DHCP nameservers (default: "default")
    --foreman-proxy-dhcp-omapi-port  DHCP server OMAPI port (default: 7911)
    --foreman-proxy-dhcp-option-domain  DHCP use the dhcpd config option domain-name (default: ["localdomain"])
    --foreman-proxy-dhcp-provider  DHCP provider (default: "isc")
    --foreman-proxy-dhcp-range    Space-separated DHCP pool range (default: false)
    --foreman-proxy-dhcp-search-domains  DHCP search domains option (default: nil)
    --foreman-proxy-dhcp-server   Address of DHCP server to manage (default: "127.0.0.1")
    --foreman-proxy-dhcp-subnets  Subnets list to restrict DHCP management to (default: [])
    --foreman-proxy-dir           Foreman proxy install directory (default: "/usr/share/foreman-proxy")
    --foreman-proxy-dns           Enable DNS feature (default: false)
    --foreman-proxy-dns-forwarders  DNS forwarders (default: [])
    --foreman-proxy-dns-interface  DNS interface (default: "eth0")
    --foreman-proxy-dns-listen-on  DNS proxy to listen on https, http, or both (default: "https")
    --foreman-proxy-dns-managed   DNS is managed by Foreman proxy (default: true)
    --foreman-proxy-dns-provider  DNS provider (default: "nsupdate")
    --foreman-proxy-dns-reverse   DNS reverse zone name (default: "100.168.192.in-addr.arpa")
    --foreman-proxy-dns-server    Address of DNS server to manage (default: "127.0.0.1")
    --foreman-proxy-dns-tsig-keytab  Kerberos keytab for DNS updates using GSS-TSIG authentication (default: "/etc/foreman-proxy/dns.keytab")
    --foreman-proxy-dns-tsig-principal  Kerberos principal for DNS updates using GSS-TSIG authentication (default: "foremanproxy/katello.localdomain@LOCALDOMAIN")
    --foreman-proxy-dns-ttl       DNS default TTL override (default: "86400")
    --foreman-proxy-dns-zone      DNS zone name (default: "localdomain")
    --foreman-proxy-ensure-packages-version  control extra packages version, it's passed to ensure parameter of package resource
                                  can be set to 'installed', 'present', 'latest', 'absent' (default: "present")
    --foreman-proxy-foreman-base-url  Base Foreman URL used for REST interaction (default: "https://katello.localdomain")
    --foreman-proxy-foreman-ssl-ca  SSL CA used to verify connections when accessing the Foreman API.
                                  When not specified, the ssl_ca is used instead. (default: "/etc/foreman-proxy/foreman_ssl_ca.pem")
    --foreman-proxy-foreman-ssl-cert  SSL client certificate used when accessing the Foreman API
                                  When not specified, the ssl_cert is used instead. (default: "/etc/foreman-proxy/foreman_ssl_cert.pem")
    --foreman-proxy-foreman-ssl-key  Corresponding key to a foreman_ssl_cert certificate
                                  When not specified, the ssl_key is used instead. (default: "/etc/foreman-proxy/foreman_ssl_key.pem")
    --foreman-proxy-freeipa-remove-dns  Remove DNS entries from FreeIPA when deleting hosts from realm (default: true)
    --foreman-proxy-gpgcheck      Turn on/off gpg check in repo files (effective only on RedHat family systems) (default: true)
    --foreman-proxy-http          Enable HTTP (default: false)
    --foreman-proxy-http-port     HTTP port to listen on (if http is enabled) (default: "8000")
    --foreman-proxy-keyfile       DNS server keyfile path (default: "/etc/rndc.key")
    --foreman-proxy-libvirt-connection  Connection string of libvirt DNS/DHCP provider (e.g. "qemu:///system") (default: "qemu:///system")
    --foreman-proxy-libvirt-network  Network for libvirt DNS/DHCP provider (default: "default")
    --foreman-proxy-log           Foreman proxy log file, 'STDOUT' or 'SYSLOG' (default: "/var/log/foreman-proxy/proxy.log")
    --foreman-proxy-log-buffer    Log buffer size (default: 2000)
    --foreman-proxy-log-buffer-errors  Additional log buffer size for errors (default: 1000)
    --foreman-proxy-log-level     Foreman proxy log level: WARN, DEBUG, ERROR, FATAL, INFO, UNKNOWN (default: "INFO")
    --foreman-proxy-logs          Enable Logs (log buffer) feature (default: true)
    --foreman-proxy-logs-listen-on  Logs proxy to listen on https, http, or both (default: "https")
    --foreman-proxy-manage-puppet-group  Whether to ensure the $puppet_group exists.  Also ensures group owner of ssl keys and certs is $puppet_group
                                  Not applicable when ssl is false. (default: true)
    --foreman-proxy-manage-sudoersd  Whether to manage File['/etc/sudoers.d'] or not.  When reusing this module, this may be
                                  disabled to let a dedicated sudo module manage it instead. (default: true)
    --foreman-proxy-mcollective-user  The user for puppetrun_provider mcollective (default: "root")
    --foreman-proxy-oauth-consumer-key  OAuth key to be used for REST interaction (default: "WRDZ2HMe5HwBfMiuyzmPk6fGpqSyyHfy")
    --foreman-proxy-oauth-consumer-secret  OAuth secret to be used for REST interaction (default: "J7qZFopiMhiR2XETdP4PbAr4FJT8kCkE")
    --foreman-proxy-oauth-effective-user  User to be used for REST interaction (default: "admin")
    --foreman-proxy-plugin-version  foreman plugins version, it's passed to ensure parameter of plugins package resource
                                  can be set to 'latest', 'present',  'installed', 'absent'. (default: "installed")
    --foreman-proxy-puppet        Enable Puppet module for environment imports and Puppet runs (default: true)
    --foreman-proxy-puppet-group  Groups of Foreman proxy user (default: "puppet")
    --foreman-proxy-puppet-listen-on  Puppet feature to listen on https, http, or both (default: "https")
    --foreman-proxy-puppet-ssl-ca  SSL CA used to verify connections when accessing the Puppet master API (default: "/etc/puppetlabs/puppet/ssl/certs/ca.pem")
    --foreman-proxy-puppet-ssl-cert  SSL certificate used when accessing the Puppet master API (default: "/etc/puppetlabs/puppet/ssl/certs/katello.localdomain.pem")
    --foreman-proxy-puppet-ssl-key  SSL private key used when accessing the Puppet master API (default: "/etc/puppetlabs/puppet/ssl/private_keys/katello.localdomain.pem")
    --foreman-proxy-puppet-url    URL of the Puppet master itself for API requests (default: "https://katello.localdomain:8140")
    --foreman-proxy-puppet-use-cache  Whether to enable caching of puppet classes (default: nil)
    --foreman-proxy-puppet-use-environment-api  Override use of Puppet's API to list environments.  When unset, the proxy will
                                  try to determine this automatically. (default: nil)
    --foreman-proxy-puppet-user   Which user to invoke sudo as to run puppet commands (default: "root")
    --foreman-proxy-puppetca      Enable Puppet CA feature (default: true)
    --foreman-proxy-puppetca-cmd  Puppet CA command to be allowed in sudoers (default: "/opt/puppetlabs/bin/puppet cert")
    --foreman-proxy-puppetca-listen-on  Puppet CA feature to listen on https, http, or both (default: "https")
    --foreman-proxy-puppetdir     Puppet var directory (default: "/etc/puppetlabs/puppet")
    --foreman-proxy-puppetrun-cmd  Puppet run/kick command to be allowed in sudoers (default: "/opt/puppetlabs/bin/puppet kick")
    --foreman-proxy-puppetrun-provider  Provider for running/kicking Puppet agents (default: nil)
    --foreman-proxy-puppetssh-command  The command used by puppetrun_provider puppetssh (default: "/usr/bin/puppet agent --onetime --no-usecacheonfailure")
    --foreman-proxy-puppetssh-keyfile  The keyfile for puppetrun_provider puppetssh commands (default: "/etc/foreman-proxy/id_rsa")
    --foreman-proxy-puppetssh-sudo  Whether to use sudo before commands when using puppetrun_provider puppetssh (default: false)
    --foreman-proxy-puppetssh-user  The user for puppetrun_provider puppetssh (default: "root")
    --foreman-proxy-puppetssh-wait  Whether to wait for completion of the Puppet command over SSH and return
                                  the exit code (default: false)
    --foreman-proxy-realm         Enable realm management feature (default: false)
    --foreman-proxy-realm-keytab  Kerberos keytab path to authenticate realm updates (default: "/etc/foreman-proxy/freeipa.keytab")
    --foreman-proxy-realm-listen-on  Realm proxy to listen on https, http, or both (default: "https")
    --foreman-proxy-realm-principal  Kerberos principal for realm updates (default: "realm-proxy@EXAMPLE.COM")
    --foreman-proxy-realm-provider  Realm management provider (default: "freeipa")
    --foreman-proxy-register-in-foreman  Register proxy back in Foreman (default: true)
    --foreman-proxy-registered-name  Proxy name which is registered in Foreman (default: "katello.localdomain")
    --foreman-proxy-registered-proxy-url  Proxy URL which is registered in Foreman (default: nil)
    --foreman-proxy-repo          This can be stable, rc, or nightly (default: "stable")
    --foreman-proxy-salt-puppetrun-cmd  Salt command to trigger Puppet run (default: "puppet.run")
    --foreman-proxy-ssl           Enable SSL, ensure feature is added with "https://" protocol if true (default: true)
    --foreman-proxy-ssl-ca        SSL CA to validate the client certificates used to access the proxy (default: "/etc/foreman-proxy/ssl_ca.pem")
    --foreman-proxy-ssl-cert      SSL certificate to be used to run the foreman proxy via https. (default: "/etc/foreman-proxy/ssl_cert.pem")
    --foreman-proxy-ssl-disabled-ciphers  List of OpenSSL cipher suite names that will be disabled from the default (default: [])
    --foreman-proxy-ssl-key       Corresponding key to a ssl_cert certificate (default: "/etc/foreman-proxy/ssl_key.pem")
    --foreman-proxy-ssl-port      HTTPS port to listen on (if ssl is enabled) (default: 9090)
    --foreman-proxy-ssldir        Puppet CA ssl directory (default: "/etc/puppetlabs/puppet/ssl")
    --foreman-proxy-template-url  URL a client should use for provisioning templates (default: "http://katello.localdomain:8000")
    --foreman-proxy-templates     Enable templates feature (default: false)
    --foreman-proxy-templates-listen-on  Templates proxy to listen on https, http, or both (default: "both")
    --foreman-proxy-tftp          Enable TFTP feature (default: false)
    --foreman-proxy-tftp-dirs     Directories to be create in $tftp_root (default: ["/var/lib/tftpboot/pxelinux.cfg", "/var/lib/tftpboot/grub", "/var/lib/tftpboot/grub2", "/var/lib/tftpboot/boot", "/var/lib/tftpboot/ztp.cfg", "/var/lib/tftpboot/poap.cfg"])
    --foreman-proxy-tftp-listen-on  TFTP proxy to listen on https, http, or both (default: "https")
    --foreman-proxy-tftp-manage-wget  If enabled will install the wget package (default: true)
    --foreman-proxy-tftp-managed  TFTP is managed by Foreman proxy (default: true)
    --foreman-proxy-tftp-root     TFTP root directory (default: "/var/lib/tftpboot")
    --foreman-proxy-tftp-servername  Defines the TFTP Servername to use, overrides the name in the subnet declaration (default: nil)
    --foreman-proxy-tftp-syslinux-filenames  Syslinux files to install on TFTP (full paths) (default: ["/usr/share/syslinux/chain.c32", "/usr/share/syslinux/mboot.c32", "/usr/share/syslinux/menu.c32", "/usr/share/syslinux/memdisk", "/usr/share/syslinux/pxelinux.0"])
    --foreman-proxy-trusted-hosts  Only hosts listed will be permitted, empty array to disable authorization (default: ["katello.localdomain"])
    --foreman-proxy-use-sudoersd  Add a file to /etc/sudoers.d (true) or uses augeas (false) (default: true)
    --foreman-proxy-user          User under which foreman proxy will run (default: "foreman-proxy")
    --foreman-proxy-version       foreman package version, it's passed to ensure parameter of package resource
                                  can be set to specific version number, 'latest', 'present' etc. (default: "present")


= Module foreman_proxy_plugin_openscap:
    --foreman-proxy-plugin-openscap-configure-openscap-repo  Enable custom yum repo with packages needed for smart_proxy_openscap, (default: false)
    --foreman-proxy-plugin-openscap-contentdir  Directory where OpenSCAP content XML are stored
                                  So we will not request the XML from Foreman each time (default: "/var/lib/foreman-proxy/openscap/content")
    --foreman-proxy-plugin-openscap-failed-dir  Directory where OpenSCAP report XML are stored
                                  In case sending to Foreman succeeded, yet failed to save to reportsdir (default: "/var/lib/foreman-proxy/openscap/failed")
    --foreman-proxy-plugin-openscap-openscap-send-log-file  Log file for the forwarding script (default: "/var/log/foreman-proxy/openscap-send.log")
    --foreman-proxy-plugin-openscap-reportsdir  Directory where OpenSCAP report XML are stored
                                  So Foreman can request arf xml reports (default: "/var/lib/foreman-proxy/openscap/reports")
    --foreman-proxy-plugin-openscap-spooldir  Directory where OpenSCAP audits are stored
                                  before they are forwarded to Foreman (default: "/var/spool/foreman-proxy/openscap")


= Module foreman_proxy_plugin_pulp:


= Module foreman_proxy_plugin_remote_execution_ssh:
    --foreman-proxy-plugin-remote-execution-ssh-generate-keys  Automatically generate SSH keys (default: true)
    --foreman-proxy-plugin-remote-execution-ssh-local-working-dir  Local working directory on the smart proxy (default: "/var/tmp")
    --foreman-proxy-plugin-remote-execution-ssh-remote-working-dir  Remote working directory on clients (default: "/var/tmp")
    --foreman-proxy-plugin-remote-execution-ssh-ssh-identity-dir  Directory where SSH keys are stored (default: "/usr/share/foreman-proxy/.ssh")
    --foreman-proxy-plugin-remote-execution-ssh-ssh-identity-file  Provide an alternative name for the SSH keys (default: "id_rsa_foreman_proxy")
    --foreman-proxy-plugin-remote-execution-ssh-ssh-keygen  Location of the ssh-keygen binary (default: "/usr/bin/ssh-keygen")


= Module katello:
    --katello-cdn-ssl-version     SSL version used to communicate with the CDN. Optional. Use SSLv23 or TLSv1 (default: nil)
    --katello-config-dir          Location for Katello config files (default: "/etc/foreman/plugins")
    --katello-enable-ostree       Boolean to enable ostree plugin. This requires existence of an ostree install. (default: false)
    --katello-group               The Katello system user group (default: "foreman")
    --katello-log-dir             Location for Katello log files to be placed (default: "/var/log/foreman/plugins")
    --katello-max-keep-alive      Maximum number of requests to use for the apache MaxKeepAliveRequests parameter
                                  on the virtualHost for port 443. (default: 10000)
    --katello-num-pulp-workers    Number of pulp workers to use (default: 2)
    --katello-oauth-key           The oauth key for talking to the candlepin API (default: "katello")
    --katello-oauth-secret        The oauth secret for talking to the candlepin API (default: "YzoRFEHNZnMZyvyprbKTV9zbCjNBHvkP")
    --katello-package-names       Packages that this module ensures are present instead of the default (default: ["katello", "tfm-rubygem-katello"])
    --katello-post-sync-token     The shared secret for pulp notifying katello about
                                  completed syncs (default: "ozfpMginFiCpgRy65Tqdq9SoUq7z45bP")
    --katello-proxy-password      Proxy password for authentication (default: nil)
    --katello-proxy-port          Port the proxy is running on (default: nil)
    --katello-proxy-url           URL of the proxy server (default: nil)
    --katello-proxy-username      Proxy username for authentication (default: nil)
    --katello-repo-export-dir     Directory to create for repository exports (default: "/var/lib/pulp/katello-export")
    --katello-user                The Katello system user name (default: "foreman")
    --katello-user-groups         Extra user groups the Katello user is a part of (default: "foreman")
