#ifndef UPDATE_MANAGER_H
#define UPDATE_MANAGER_H

#include "sysrepo.h"
#include "sysrepo/values.h"

#ifndef MIN
#define MIN(a,b)        (((a)<(b))?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b)        (((a)>(b))?(a):(b))
#endif


#define ARRAYSIZE(arr)  (sizeof(arr) / sizeof(arr[0]))
#define MAX_STR_SIZE    512

#define PROG_NAME           "update_manager"
#define CONFIG_FILE         "config.xsp"
#define CONFIG_DIR          "/etc/sentry"
#define FULL_CONFIG_FILE    "/etc/sentry/config.xsp"
#define OLD_CONFIG_FILE     "/etc/sentry/config.old"
#define TMP_FILE            "/etc/sentry/confing.tmp"
#define VERSION_FILE        "/etc/sentry/version"

#define LOG_DIR             "/var/log"
#define LOG_FILE            "sentry.log"
#define MAX_LOG_FILE_NUM    10

#define MAX_LOG_BUFFER_SIZE 0x2000
#define LOG_UPLOAD_INTERVAL 1 /*in secs*/
#define UPDATE_VER_INTERVAL 1 /*in secs*/
#define DEMO_VIN_FILE       "/etc/sentry/vin"
#define DEMO_VIN            "OpenSentryDEMO123"
#define LOG_SERVER_PATH     "/tmp/sentry_srv"

#define ACT_PREFIX   "/saferide:config/sr_actions/list_actions["
#define CAN_PREFIX   "/saferide:config/net/can/rule["
#define IP_PREFIX    "/saferide:config/net/ip/rule["
#define FILE_PREFIX  "/saferide:config/system/file/rule["

typedef struct {
    char*       name;
    sr_type_t   type;
    void*       value;
} param_t;

enum {
    SUB_TYPE_NONE,
    SUB_TYPE_RULE,
    SUB_TYPE_TUPLE,
    SUB_TYPE_MAX = SUB_TYPE_TUPLE,
    SUB_TYPE_TOTAL = (SUB_TYPE_MAX + 1),
};

enum {
    TYPE_NONE,
    TYPE_ACTION,
    TYPE_FILE,
    TYPE_IP,
    TYPE_CAN,
    TYPE_MAX = TYPE_CAN,
    TYPE_TOTAL = (TYPE_MAX + 1),
};

#define updatem_debug(fmt, args...) \
    fprintf(stderr, "DEBUG: %s(): " fmt, __func__, ##args)
#define updatem_error(fmt, args...) \
    fprintf(stderr, "ERROR: %s(): " fmt, __func__, ##args)
#define updatem_warn(fmt, args...) \
    fprintf(stderr, "WARN: %s(): " fmt, __func__, ##args)

int get_remote_version(char *version);
int download_latest_policy(char *new_version);
int upload_log_file(char* filename, int offset);
void set_server_address(char* address);
void remote_update_init(void);
void remote_update_deinit(void);

#endif
