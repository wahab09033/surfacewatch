"""Static wordlists and port profiles used by the scanning modules.

Kept in-tree so a worker container needs no external data files. The subdomain
list is the high-signal head of the usual public lists — enough to find the
common exposures without a 100k-request bruteforce.
"""

from __future__ import annotations

SUBDOMAIN_WORDLIST: tuple[str, ...] = (
    # Web / edge
    "www", "www2", "web", "webapp", "app", "apps", "portal", "cdn", "static",
    "assets", "img", "images", "media", "files", "download", "downloads",
    # Environments
    "dev", "development", "test", "testing", "qa", "uat", "stage", "staging",
    "sandbox", "demo", "preview", "beta", "alpha", "prod", "production",
    "local", "internal", "int", "corp", "intranet",
    # API / services
    "api", "api-dev", "api-staging", "apis", "rest", "graphql", "gateway",
    "gw", "service", "services", "microservice", "rpc", "grpc", "ws",
    "websocket", "socket", "stream", "events", "webhook", "webhooks",
    # Auth / identity
    "auth", "sso", "login", "signin", "account", "accounts", "id", "identity",
    "oauth", "idp", "saml", "ldap", "keycloak", "okta",
    # Admin / ops
    "admin", "administrator", "adminpanel", "cpanel", "whm", "plesk", "manage",
    "management", "console", "dashboard", "panel", "backoffice", "ops",
    "operations", "root", "sysadmin",
    # Mail
    "mail", "smtp", "imap", "pop", "pop3", "webmail", "email", "mx", "mx1",
    "mx2", "exchange", "owa", "autodiscover", "mailgun", "postfix", "relay",
    # Infra
    "vpn", "remote", "rdp", "ssh", "sftp", "ftp", "ftps", "bastion", "jump",
    "proxy", "haproxy", "nginx", "apache", "lb", "loadbalancer", "router",
    "firewall", "fw", "gateway2", "ns", "ns1", "ns2", "ns3", "ns4", "dns",
    "dns1", "dns2", "resolver",
    # Data
    "db", "database", "mysql", "postgres", "postgresql", "pgsql", "mssql",
    "oracle", "mongo", "mongodb", "redis", "memcached", "cassandra", "couch",
    "elastic", "elasticsearch", "es", "kibana", "solr", "influx", "clickhouse",
    "warehouse", "datalake", "bi", "analytics", "metabase", "superset",
    # CI/CD, source, registries
    "git", "gitlab", "github", "bitbucket", "svn", "jenkins", "ci", "cd",
    "build", "builds", "drone", "travis", "teamcity", "bamboo", "argo",
    "nexus", "artifactory", "registry", "docker", "harbor", "npm", "pypi",
    # Observability
    "grafana", "prometheus", "metrics", "monitor", "monitoring", "nagios",
    "zabbix", "sentry", "logs", "log", "logging", "kibana2", "graylog",
    "jaeger", "status", "health", "uptime", "alerts", "alertmanager",
    # Collaboration / internal tools
    "jira", "confluence", "wiki", "docs", "documentation", "support",
    "helpdesk", "ticket", "tickets", "servicedesk", "crm", "erp", "hr",
    "intranet2", "sharepoint", "teams", "chat", "mattermost", "rocketchat",
    # Orchestration
    "k8s", "kubernetes", "kube", "rancher", "openshift", "consul", "vault",
    "nomad", "etcd", "swarm", "mesos", "airflow", "spark",
    # Commerce / content
    "shop", "store", "checkout", "pay", "payment", "payments", "billing",
    "invoice", "blog", "news", "forum", "community", "cms", "wordpress", "wp",
    "drupal", "joomla", "magento", "shopify",
    # Cloud / misc
    "s3", "storage", "backup", "backups", "archive", "old", "legacy", "new",
    "tmp", "temp", "test2", "mobile", "m", "ios", "android", "video",
    "conference", "meet", "zoom", "voip", "sip", "pbx", "asterisk",
    "smtp2", "mail2", "secure", "ssl", "cert", "ca", "crl", "ocsp",
)


# --- Port profiles ----------------------------------------------------------

# nmap's top-100 TCP ports by open frequency.
TOP_100_PORTS: tuple[int, ...] = (
    7, 9, 13, 21, 22, 23, 25, 26, 37, 53, 79, 80, 81, 88, 106, 110, 111, 113,
    119, 135, 139, 143, 144, 179, 199, 389, 427, 443, 444, 445, 465, 513, 514,
    515, 543, 544, 548, 554, 587, 631, 646, 873, 990, 993, 995, 1025, 1026,
    1027, 1028, 1029, 1110, 1433, 1720, 1723, 1755, 1900, 2000, 2001, 2049,
    2121, 2717, 3000, 3128, 3306, 3389, 3986, 4899, 5000, 5009, 5051, 5060,
    5101, 5190, 5357, 5432, 5631, 5666, 5800, 5900, 6000, 6001, 6646, 7070,
    8000, 8008, 8009, 8080, 8081, 8443, 8888, 9100, 9999, 10000, 32768, 49152,
    49153, 49154, 49155, 49156, 49157,
)

# Ports that matter most for an internet-facing surface review: the top-100
# plus databases, caches, orchestration APIs and admin panels that show up
# exposed in real engagements.
TOP_1000_EXTRA: tuple[int, ...] = (
    20, 69, 123, 137, 138, 161, 162, 264, 280, 311, 500, 512, 593, 623, 636,
    691, 705, 777, 800, 808, 843, 880, 888, 898, 901, 992, 1000, 1080, 1099,
    1194, 1352, 1434, 1521, 1604, 1812, 1883, 2082, 2083, 2086, 2087, 2095,
    2096, 2181, 2222, 2375, 2376, 2379, 2380, 2404, 2483, 2484, 2601, 2604,
    3001, 3002, 3268, 3299, 3307, 3333, 3690, 4000, 4040, 4200, 4243, 4369,
    4444, 4505, 4506, 4567, 4786, 4840, 4848, 5001, 5002, 5005, 5010, 5044,
    5222, 5269, 5353, 5355, 5555, 5601, 5672, 5673, 5701, 5850, 5901, 5902,
    5984, 5985, 5986, 6066, 6379, 6443, 6666, 6667, 7000, 7001, 7002, 7077,
    7080, 7180, 7199, 7443, 7474, 7547, 7687, 7777, 8005, 8010, 8020, 8025,
    8030, 8069, 8086, 8087, 8088, 8089, 8090, 8091, 8098, 8099, 8123, 8161,
    8180, 8181, 8200, 8222, 8280, 8281, 8333, 8400, 8500, 8529, 8530, 8531,
    8686, 8800, 8834, 8880, 8983, 9000, 9001, 9002, 9042, 9043, 9060, 9080,
    9090, 9091, 9092, 9200, 9201, 9300, 9418, 9443, 9500, 9600, 9800, 9981,
    9990, 9998, 10001, 10250, 10255, 10443, 11211, 11214, 11215, 15672,
    16010, 16992, 16993, 18080, 20000, 20720, 25565, 27017, 27018, 27019,
    28017, 32764, 33060, 44818, 47001, 47808, 50000, 50030, 50060, 50070,
    50100, 55553, 61616, 61621,
)

TOP_1000_PORTS: tuple[int, ...] = tuple(sorted(set(TOP_100_PORTS) | set(TOP_1000_EXTRA)))

WEB_PORTS: tuple[int, ...] = (
    80, 81, 88, 443, 444, 591, 593, 832, 981, 1010, 1311, 2082, 2087, 2095,
    2096, 2480, 3000, 3128, 3333, 4243, 4443, 4567, 4711, 4712, 4993, 5000,
    5104, 5108, 5280, 5281, 5601, 5800, 6543, 7000, 7001, 7396, 7474, 8000,
    8001, 8008, 8014, 8042, 8060, 8069, 8080, 8081, 8083, 8088, 8090, 8091,
    8118, 8123, 8172, 8181, 8222, 8243, 8280, 8281, 8333, 8443, 8500, 8834,
    8880, 8888, 8983, 9000, 9043, 9060, 9080, 9090, 9091, 9200, 9443, 9800,
    9981, 12443, 16080, 18091, 18092, 20720, 55672,
)


def resolve_port_profile(profile: str, custom: list[int] | None = None) -> list[int]:
    """Turn a scan config's port profile into an explicit port list."""
    if profile == "custom":
        return sorted(set(custom or [])) or list(TOP_100_PORTS)
    if profile == "top-100":
        return list(TOP_100_PORTS)
    if profile == "web":
        return list(WEB_PORTS)
    if profile == "full":
        return list(range(1, 65536))
    return list(TOP_1000_PORTS)


# --- Service hints ----------------------------------------------------------

# Port -> conventional service name, used when no banner is returned.
COMMON_SERVICES: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 80: "http",
    110: "pop3", 111: "rpcbind", 135: "msrpc", 139: "netbios-ssn",
    143: "imap", 161: "snmp", 389: "ldap", 443: "https", 445: "smb",
    465: "smtps", 587: "submission", 636: "ldaps", 873: "rsync",
    993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    2375: "docker", 2376: "docker-tls", 2379: "etcd", 3000: "http-alt",
    3306: "mysql", 3389: "rdp", 5432: "postgresql", 5601: "kibana",
    5672: "amqp", 5900: "vnc", 5984: "couchdb", 6379: "redis",
    6443: "kubernetes-api", 7001: "weblogic", 8000: "http-alt",
    8009: "ajp13", 8080: "http-proxy", 8443: "https-alt", 8888: "http-alt",
    9000: "http-alt", 9042: "cassandra", 9092: "kafka", 9200: "elasticsearch",
    9300: "elasticsearch-transport", 10250: "kubelet", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb", 50070: "hadoop-namenode",
}

__all__ = [
    "COMMON_SERVICES",
    "SUBDOMAIN_WORDLIST",
    "TOP_100_PORTS",
    "TOP_1000_PORTS",
    "WEB_PORTS",
    "resolve_port_profile",
]
