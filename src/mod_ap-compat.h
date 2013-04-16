/*
 * track API changes in http-devel
 */

#define GRST_AP_VERSION (AP_SERVER_MAJORVERSION_NUMBER * 10000 + AP_SERVER_MINORVERSION_NUMBER * 100 + AP_SERVER_PATCHLEVEL_NUMBER)

/*
 * since >=2.3.0: unixd_config -> ap_unixd_config
 */
#if GRST_AP_VERSION < 20300
#define ap_unixd_config (unixd_config)
#endif

/*
 * since >=2.3.6: loglevel -> log.level
 */
#if GRST_AP_VERSION < 20306
#define GRST_AP_LOGLEVEL(REQ) ((REQ)->loglevel)
#else
#define GRST_AP_LOGLEVEL(REQ) ((REQ)->log.level)
#endif

/*
 * since >=2.3.16: remote_ip -> (peer_ip ->) -> client_ip
 */
#if GRST_AP_VERSION < 20316
#define GRST_AP_CLIENT_IP(CONN) ((CONN)->remote_ip)
#else
#define GRST_AP_CLIENT_IP(CONN) ((CONN)->client_ip)
#endif
