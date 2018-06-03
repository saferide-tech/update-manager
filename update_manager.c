#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <errno.h>
#include <string.h>
#include <stdarg.h>
#include <poll.h>
#include <sys/inotify.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pthread.h>
#include <signal.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <semaphore.h>
#include "update_manager.h"

static int pipe_fds[2];
static int debug_level = LEVEL_ERROR;
static char config_dir[MAX_STR_SIZE];
static char config_file_full[MAX_STR_SIZE];
static unsigned char background = 0;

static param_t default_action_params[] = {
    {"action", SR_STRING_T, "allow"},
    {"log/log_facility", SR_STRING_T, "none"},
    {"log/log_severity", SR_STRING_T, "none"},
    {"black-list", SR_BOOL_T, false},
    {"terminate", SR_BOOL_T, false}
};

static param_t default_can_tuple_params[] = {
    {"msg_id", SR_STRING_T, "000"},
    {"direction", SR_STRING_T, "out"},
    {"user", SR_STRING_T, ""},
    {"program", SR_STRING_T, ""},
    {"max_rate", SR_UINT32_T, 0}
};

static param_t default_file_tuple_params[] = {
    {"filename", SR_STRING_T, ""},
    {"permission", SR_STRING_T, "000"},
    {"user", SR_STRING_T, ""},
    {"program", SR_STRING_T, ""},
    {"max_rate", SR_UINT32_T, 0}
};

static param_t default_ip_tuple_params[] = {
    {"srcaddr", SR_STRING_T, "0.0.0.0"},
    {"srcnetmask", SR_STRING_T, "0.0.0.0"},
    {"dstaddr", SR_STRING_T, "0.0.0.0"},
    {"dstnetmask", SR_STRING_T, "0.0.0.0"},
    {"proto", SR_UINT8_T, 0},
    {"srcport", SR_UINT16_T, 0},
    {"dstport", SR_UINT16_T, 0},
    {"user", SR_STRING_T, ""},
    {"program", SR_STRING_T, ""},
    {"max_rate", SR_UINT32_T, 0}
};

static param_t default_rule_params[] = {
    {"action", SR_STRING_T, ""},
};

/***********************************************************************
 * function:    set_str_value
 * description: this function convert a string the relevant type and
 *              set the value
 * in param:    sr_val_t *value
 *              char* str_value
 * return:      SR_ERR_OK/SR_ERR_XXX
 **********************************************************************/
static int set_str_value(sr_val_t *value, char* str_value)
{
    int rc = SR_ERR_OK;

    if (!value) {
        updatem_error("invalid arg\n");
        return SR_ERR_INVAL_ARG;
    }

    switch (value->type) {
    case SR_BOOL_T:
        if (strncmp(str_value, "false", strlen(str_value)) == 0)
            value->data.bool_val = false;
        else
            value->data.bool_val = true;
        break;
    case SR_INT8_T:
        value->data.int8_val = atoi(str_value);
        break;
    case SR_INT16_T:
        value->data.int16_val = atoi(str_value);
        break;
    case SR_INT32_T:
        value->data.int32_val = atoi(str_value);
        break;
    case SR_UINT8_T:
        value->data.uint8_val = atoi(str_value);
        break;
    case SR_UINT16_T:
        value->data.uint16_val = atoi(str_value);
        break;
    case SR_UINT32_T:
        value->data.uint32_val = atoi(str_value);
        break;
    case SR_STRING_T:
        value->data.string_val = str_value;
        break;
    default:
        updatem_error("unsupported value type\n");
        rc = SR_ERR_UNSUPPORTED;
        break;
    }

    return rc;
}

/* this function is used when we create new entry and we need to fill it with
 * some default param. for example, if we create new rule, the action reference
 * nee to be set.*/
/***********************************************************************
 * function:    set_default_params
 * description: this function is used when we create new entry and we
 *              need to fill it with some default param.
 *              for example, if we create new rule, the action reference
 *              need to be set
 * in param:    sr_session_ctx_t *sess
 *              char *xpath
 *              param_t* ptr,
 *              int size
 * return:      SR_ERR_OK/SR_ERR_XXX
 **********************************************************************/
static int set_default_params(sr_session_ctx_t *sess, char *xpath, param_t* ptr,
    int size)
{
    int rc = SR_ERR_OK, i;
    sr_val_t value = {0};
    char param_xpath[MAX_STR_SIZE];

    for (i=0; i<size; i++) {
        /* prepare the xpath of the tuple parameter */
        snprintf(param_xpath, MAX_STR_SIZE, "%s/%s",xpath, ptr[i].name);

        /* init the value and type*/
        value.type = ptr[i].type;
        switch(value.type) {
        case SR_STRING_T:
            value.data.string_val = (char*)ptr[i].value;
            break;
        case SR_UINT8_T:
            value.data.uint8_val = 0;
            break;
        case SR_UINT16_T:
            value.data.uint16_val = 0;
            break;
        case SR_UINT32_T:
            value.data.uint32_val = 0;
            break;
        case SR_BOOL_T:
            value.data.bool_val = ptr[i].value;
            break;
        default:
            updatem_error("this type (%d) not supported\n", value.type);
            rc = SR_ERR_UNSUPPORTED;
            break;
        }

        if (rc == SR_ERR_OK) {
            /* set the default value */
            rc = sr_set_item(sess, param_xpath, &value, SR_EDIT_DEFAULT);
            if (SR_ERR_OK != rc)
                updatem_error("sr_set_item %s: %s\n", param_xpath,
                    sr_strerror(rc));
        }
    }

    return rc;
}

/***********************************************************************
 * function:    get_entry_type
 * description: return the type and subtype of entry
 *              TYPE_ACTION/TYPE_CAN/TYPE_IP/TYPE_FILE
 *              SUB_TYPE_RULE/SUB_TYPE_TUPLE
 * in param:    char *entry
 * out param:   int *p_type
 *              int *p_sub_type
 * return:      n/a
 **********************************************************************/
static void get_entry_type(int *p_type, int *p_sub_type, char *entry)
{
    char *tmp;
    int len = 0;

    if (!p_type || !p_sub_type || !p_sub_type)
        return;

    /* check if this is an action/rule entry*/
    if (strncmp(entry, ACT_PREFIX, strlen(ACT_PREFIX)) == 0) {
        *p_type = TYPE_ACTION;
        return;
    } else if (strncmp(entry, CAN_PREFIX, strlen(CAN_PREFIX)) == 0) {
        *p_type = TYPE_CAN;
        *p_sub_type = SUB_TYPE_RULE;
        len = strlen(CAN_PREFIX);
    } else if (strncmp(entry, IP_PREFIX, strlen(IP_PREFIX)) == 0) {
        *p_type = TYPE_IP;
        *p_sub_type = SUB_TYPE_RULE;
        len = strlen(IP_PREFIX);
    } else if (strncmp(entry, FILE_PREFIX, strlen(FILE_PREFIX)) == 0) {
        *p_type = TYPE_FILE;
        *p_sub_type = SUB_TYPE_RULE;
        len = strlen(FILE_PREFIX);
    } else {
        /* unknown */
        return;
    }

    tmp = entry+len;
    /* check if it is a tuple */
    if (strstr(tmp, "]/tuple[id="))
        *p_sub_type = SUB_TYPE_TUPLE;
}

/***********************************************************************
 * function:    update_policy
 * description: this function read the current security policy config and update the
 *              sysrepo sdatabase.
 * in param:    sr_session_ctx_t *sess
 * return:      SR_ERR_OK/SR_ERR_XXX
 **********************************************************************/
static int update_policy(sr_session_ctx_t *sess)
{
    FILE *config_file = NULL;
    char buffer[MAX_STR_SIZE], str_param[MAX_STR_SIZE], str_value[MAX_STR_SIZE];
    int rc = SR_ERR_OK, items;
    sr_val_t *value = NULL, new_val = {0};
    char* tmp;

    snprintf(config_file_full, MAX_STR_SIZE, "%s/%s", config_dir, CONFIG_FILE); 
    updatem_debug("reading configuration from %s\n", config_file_full);
    config_file = fopen(config_file_full, "r");
    if (config_file == NULL) {
    	updatem_debug("fopen %s: %s\n", config_file_full, strerror(errno));
    } else {
    	rc = sr_delete_item(sess, "/saferide:config", SR_EDIT_DEFAULT);
    	if (SR_ERR_OK != rc) {
    		updatem_error("sr_delete_item: %s\n", sr_strerror(rc));
    		return rc;
    	}

    	/* update changes */
    	while(fgets(buffer, MAX_STR_SIZE, config_file) != NULL) {
    		/* clear new-line */
    		tmp = strchr(buffer, '\n');
    		if (tmp)
    			*tmp = 0;

    		/* detect if this set param line or creating of new element */
    		items = sscanf(buffer, "%s = %s", str_param, str_value);
    		if (items == 1) {
    			/* new element ... create it */
    			int type = TYPE_NONE, sub_type = SUB_TYPE_NONE;
    			param_t* ptr = NULL;
    			int array_size = 0;

    			/* creating new element */
    			if (!strlen(str_param))
    				/* invalid line */
    				continue;

    			updatem_debug("creaing new element %s\n", str_param);

    			rc = sr_set_item(sess, str_param, NULL, SR_EDIT_DEFAULT);
    			if (SR_ERR_OK != rc) {
    				updatem_error("sr_set_item %s: %s\n", str_param,
    						sr_strerror(rc));
    				continue;
    			}

    			get_entry_type(&type, &sub_type, str_param);
    			switch (type) {
    			case TYPE_ACTION:
    				ptr = default_action_params;
    				array_size = ARRAYSIZE(default_action_params);
    				break;
    			case TYPE_FILE:
    				if (sub_type == SUB_TYPE_TUPLE) {
    					ptr = default_file_tuple_params;
    					array_size = ARRAYSIZE(default_file_tuple_params);
    				} else if (sub_type == SUB_TYPE_RULE) {
    					ptr = default_rule_params;
    					array_size = ARRAYSIZE(default_rule_params);
    				}
    				break;
    			case TYPE_IP:
    				if (sub_type == SUB_TYPE_TUPLE) {
    					ptr = default_ip_tuple_params;
    					array_size = ARRAYSIZE(default_ip_tuple_params);
    				} else if (sub_type == SUB_TYPE_RULE) {
    					ptr = default_rule_params;
    					array_size = ARRAYSIZE(default_rule_params);
    				}
    				break;
    			case TYPE_CAN:
    				if (sub_type == SUB_TYPE_TUPLE) {
    					ptr = default_can_tuple_params;
    					array_size = ARRAYSIZE(default_can_tuple_params);
    				} else if (sub_type == SUB_TYPE_RULE) {
    					ptr = default_rule_params;
    					array_size = ARRAYSIZE(default_rule_params);
    				}
    				break;
    			default:
    				updatem_error("can't get type of %s\n", str_param);
    				break;
    			}

    			if (ptr) {
    				rc = set_default_params(sess, str_param, ptr, array_size);
    				if (rc != SR_ERR_OK)
    					updatem_error("setting new item params to default\n");
    			}
    		} else if (items == 2) {
    			/* setting element */
    			if (!strlen(str_param) || !strlen(str_value)) {
    				/* invalid */
    				updatem_error("invalid str_param\n");
    				continue;
    			}

    			updatem_debug("setting %s to %s\n", str_param, str_value);

    			rc = sr_get_item(sess, str_param, &value);
    			if (rc != SR_ERR_OK) {
    				updatem_error("sr_get_item %s: %s\n", str_param,
    						sr_strerror(rc));
    				continue;
    			}

    			memset(&new_val, 0, sizeof(sr_val_t));
    			new_val.type = value->type;
    			sr_free_val(value);

    			rc = set_str_value(&new_val, str_value);
    			if (rc != SR_ERR_OK) {
    				updatem_error("set_str_value failed to set %s to %s: %s\n",
    						str_param, str_value, sr_strerror(rc));
    				continue;
    			}

    			/* set the new value */
    			rc = sr_set_item(sess, str_param, &new_val, SR_EDIT_DEFAULT);
    			if (SR_ERR_OK != rc)
    				updatem_error("sr_set_item %s to %s: %s\n", str_param,
    						str_value, sr_strerror(rc));
    		}
    	}
    	/* commit the changes */
    	rc = sr_commit(sess);
    	if (SR_ERR_OK != rc)
    		updatem_error("sr_commit: %s\n", sr_strerror(rc));

    	rc = sr_copy_config(sess, "saferide", SR_DS_RUNNING, SR_DS_STARTUP);
    	if (SR_ERR_OK != rc)
    		updatem_error("sr_copy_config: %s\n", sr_strerror(rc));
    }

    return rc;
}

/* time of last log upload */
struct timeval last_upload;
 /* offset in the log file */
static unsigned long file_offset = 0;

/* log file rotation detection params */
static bool was_moved = false;
char *log_files[MAX_LOG_FILE_NUM];
char *full_log_files[MAX_LOG_FILE_NUM];
static int tracked_file_index = 0;

sem_t sem_log_uploader;

/***********************************************************************
 * function:    log_uploader
 * description: upon signal (via sem),  this thread upload the content
 *              of the current log file from current offset and update
 *              the offset based on result. 
 * in param:    
 * return:      
 **********************************************************************/
static void* log_uploader(void *data)
{
    struct stat log_file_stat;
    int ret = 0;
    bool *run = (bool*)data;

    while (*run) {
        sem_wait(&sem_log_uploader);

        if (!*run) {
            updatem_debug("log_uploader thread exiting ...\n");
            break;
        }

        if (stat(full_log_files[tracked_file_index], &log_file_stat)) {
            /* errors are expected ... its rotated log */
            updatem_error("stat: %s\n", strerror(errno));
            continue;
        }

        if (log_file_stat.st_size <= file_offset)
            /* something happend .. most likely the file was
             * renamed. lets wait for the move event and
             * continue from there */
            continue;

        //updatem_debug("uploading %s@%lu\n", full_log_files[tracked_file_index], file_offset);
        ret = upload_log_file(full_log_files[tracked_file_index], file_offset);
        if (ret > 0) {
            file_offset += ret;
            if (tracked_file_index > 0) {
                /* in such case the file is close and will not be modified,
                 * thus we can assume that we uploaded all of it and can
                 * set file_offset to 0 */
                file_offset = 0;
                tracked_file_index--;
                updatem_debug("going back to %s\n", full_log_files[tracked_file_index]);
            }
        }
    }

    pthread_detach(pthread_self());

    updatem_debug("exit!\n");

    return NULL;
}

/***********************************************************************
 * function:    check_log_events
 * description: this function read and check the events in the log directory.
 *              if the event is related to sentry log we check if we need
 *              to upload the new data in the log file
 * in param:    int fd
 * return:      
 **********************************************************************/
static int check_log_events(int fd)
{
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len = 0;
    char *ptr = NULL;
    struct stat log_file_stat;
    struct timeval current_time;

    memset(buf, 0, sizeof(buf));
    len = read(fd, buf, sizeof(buf));

    if (len <= 0) {
        if (len < 0)
            updatem_error("read: %s\n", strerror(errno));
        return 0;
    }

    for (ptr = buf; ptr < buf + len;
            ptr += sizeof(struct inotify_event) + event->len) {
        event = (const struct inotify_event *) ptr;
        if (!event->len)
            continue;

        /* check if this event is related to log file */
        if (strcmp(event->name, log_files[tracked_file_index]) == 0) {
            if (event->mask == IN_MODIFY) {
                bool force_upload = false;

                if (stat(full_log_files[tracked_file_index], &log_file_stat)) {
                    /* errors are expected ... its rotated log */
                    updatem_error("stat: %s\n", strerror(errno));
                    continue;
                }

                if (log_file_stat.st_size < file_offset)
                    /* something happend .. most likely the file was
                     * renamed. lets wait for the move event and
                     * continue from there */
                    continue;

                gettimeofday(&current_time, NULL);
                if ((current_time.tv_sec - last_upload.tv_sec) >= LOG_UPLOAD_INTERVAL)
                    force_upload = 1;

                if (force_upload ||
                    (log_file_stat.st_size - file_offset) >= MAX_LOG_BUFFER_SIZE) {
                    sem_post(&sem_log_uploader);
                }
            }

            if (event->mask == IN_MOVED_FROM) {
                /* do nothing .. wait for move to complete */
                updatem_debug("%s moved\n", log_files[tracked_file_index]);
                was_moved = true;
                continue;
            }
        }

        if (event->mask == IN_MOVED_TO) {
            if (was_moved) {
                if (tracked_file_index < (MAX_LOG_FILE_NUM-1))
                    tracked_file_index++;
                updatem_debug("to %s\n", log_files[tracked_file_index]);
                was_moved = false;
                sem_post(&sem_log_uploader);
            }
        }
    }

    return 0;
}

/***********************************************************************
 * function:    check_config_events
 * description: this function read and check the events in the config directory.
 *              if the event is related to sentry cfg we update the sysrepo db
 * in param:    
 * return:      
 **********************************************************************/
static bool check_config_events(int fd, sr_session_ctx_t *sess)
{
    char buf[4096] __attribute__ ((aligned(__alignof__(struct inotify_event))));
    const struct inotify_event *event;
    ssize_t len;
    char *ptr;

    for (;;) {
        len = read(fd, buf, sizeof buf);
        if (len == -1 && errno != EAGAIN) {
            updatem_error("read inotify fd failed: %s\n", strerror(errno));
            break;
        }

        if (len <= 0)
            break;

        for (ptr = buf; ptr < buf + len;
                ptr += sizeof(struct inotify_event) + event->len) {
            event = (const struct inotify_event *) ptr;

            if ((event->len) &&
                memcmp(event->name, CONFIG_FILE, strlen(event->name)) == 0) {
                if (event->mask & IN_CLOSE_WRITE)
                    /* config file was modified .. update sysrepo */
                    update_policy(sess);
            }
        }
    }

    return false;
}

/***********************************************************************
 * function:    monitor_file
 * description: this thread monitor the changes in config/log dir.
 *              in remote mode we monitor the log directory and upon
 *              change the relevant portion of the log will be uploaded
 *              to server. in local mode we monitor the config directory
 *              for modification and if the config file was modified, we
 *              update the sysrepo db with the changes.
 * in param:    
 * return:      n/a
 **********************************************************************/
static void* monitor_file(void *data)
{
    int fd, wd, ret;
    fd_set rfds;
    sr_session_ctx_t *sess = data;
    unsigned int notify_mask = (IN_MODIFY | IN_MOVED_FROM | IN_MOVED_TO | IN_CLOSE_WRITE);
    pthread_t thread_id;
    bool run = true;

    /* create the file descriptor for accessing the inotify API */
    fd = inotify_init1(IN_NONBLOCK);
    if (fd == -1) {
        updatem_error("inotify_init1 failed: %s\n", strerror(errno));
        return NULL;
    }

    if (sess) {
        /* this means we are working in local mode ... watch config file */
        wd = inotify_add_watch(fd, config_dir, notify_mask);
        if (wd == -1) {
            updatem_error("Cannot watch '%s': %s\n", config_dir,
                strerror(errno));
            return NULL;
        }
    } else {
        /* this means we are working in remote mode */
        sem_init(&sem_log_uploader, 0, 0);

        /* start the log uploader thread */
        ret = pthread_create(&thread_id, NULL, &log_uploader, &run);
        if (ret != 0) {
            updatem_error("pthread_create: %s\n", strerror(errno));
            return NULL;
        }

        /* start watching events on the log files */
        wd = inotify_add_watch(fd, LOG_DIR, notify_mask);
        if (wd == -1) {
            updatem_error("Cannot watch %s: %s\n", LOG_DIR, strerror(errno));
            return NULL;
        }
    }

    while (true) {
        FD_ZERO(&rfds);

        /* watch for file event or on the pipe (i.e. exit) without timeout */
        FD_SET(fd, &rfds);
        FD_SET(pipe_fds[0], &rfds);

        ret = select((MAX(fd,pipe_fds[0]) + 1), &rfds, NULL, NULL, NULL);
        if (ret < 0) {
            updatem_error("select failed: %s\n", strerror(ret));
            continue;
        }
        if (FD_ISSET(pipe_fds[0] , &rfds)) {
            /* event on pipe .. we need to exit */
            updatem_debug("monitor_file exit\n");
            if (!sess) {
                /* in remote mode signal the log upload thread to exit */
                run = false;
                sem_post(&sem_log_uploader);
            }
            break;
        }

        if (ret > 0) {
            if (sess)
                check_config_events(fd, sess);
            else
                check_log_events(fd);
        } else if (ret < 0)
            updatem_error("select failed: %s\n", strerror(ret));
    }

    close(fd);

    pthread_detach(pthread_self());

    return NULL;
}

/***********************************************************************
 * function:    get_set_current_version
 * description: read/write the current security policy from/to local file.
 * in param:    
 * return:      
 **********************************************************************/
static void get_set_current_version(bool set, char* new_version)
{
    FILE *ver_file;

    ver_file = fopen(VERSION_FILE, "w+");
    if (ver_file == NULL) {
        updatem_warn("fopen %s failed: %s\n", VERSION_FILE, strerror(errno));
        return;
    }

    if (set) {
        updatem_debug("setting new local version %s\n", new_version);
        fwrite(new_version, 1, strlen(new_version), ver_file);
    } else {
        /* read the current version */
        if (fgets(new_version, MAX_STR_SIZE, ver_file))
            updatem_debug("local version is %s\n", new_version);
    }

    fclose(ver_file);
}

/***********************************************************************
 * function:    sigint_handler
 * description: CTRL-C handler. signal to stop.
 * in param:    
 * return:      
 **********************************************************************/
static void sigint_handler(int signum)
{
    updatem_debug("received signal %d\n", signum);

    if (write(pipe_fds[1], "STOP", 4) < 0)
        updatem_error("write to pipe failed: %s\n", strerror(errno));
}

/***********************************************************************
 * function:    local_sr_print
 * description: stdin handler. signal to print sr items in local mode.
 * in param:    sr_session_ctx_t *sess
 * return:      
 **********************************************************************/
static void local_sr_print(sr_session_ctx_t *sess)
{
    int rc = SR_ERR_OK;
    char c;
    FILE *stream = stdout;
    sr_val_t *values = NULL;
    size_t count = 0;
    int i;
    uint8_t proto = 0;

    c = getchar();
    /*
     * options:
     * 'p': print rules set
     * 'c': create new configuration file
     *      works only if configuration file does not exist
     * 's': save current configuration file as OLD_CONFIG_FILE
     *      if file already exist it will be overwritten
     */
    if (c == 'p' || c == 's' || c == 'c') {

    	/* open configuration file */
    	if (c == 's') {
    		char old_config_file[MAX_STR_SIZE];
    		snprintf(old_config_file, MAX_STR_SIZE, "%s/%s", config_dir, OLD_CONFIG_FILE);
    		updatem_debug("opening old config %s\n", old_config_file);
    		stream = fopen(old_config_file, "w");
    		if (stream == NULL) {
    			updatem_error("fopen %s failed: %s\n", old_config_file, strerror(errno));
    			return;
    		}
    	} else if (c == 'c') {
    		char config_file[MAX_STR_SIZE];
    		snprintf(config_file, MAX_STR_SIZE, "%s/%s", config_dir, CONFIG_FILE);
    		stream = fopen(config_file, "r");
    		if (stream != NULL) {
    			fprintf(stdout, "Configuration file already exist\n");
    			fclose(stream);
    			return;
    		}
    		stream = fopen(config_file, "w");
    		if (stream == NULL) {
    			updatem_error("fopen %s failed: %s\n", config_file, strerror(errno));
    			return;
    		}
    	}

    	rc = sr_get_items(sess, "/saferide:*//*", &values, &count);
    	if (rc != SR_ERR_OK) {
    		updatem_debug("sr_get_items failed: (%s)\n", sr_strerror(rc));
    		fprintf(stdout, "Configuration file is empty or does not exist\n");
    		return;
    	}
    	for (i = 0; i < count; i++) {
    		switch (values[i].type) {
    		case SR_LIST_T:
    			/* print only xpath */
    			if (strstr(values[i].xpath, "/tuple") != NULL) {
    				fprintf(stream, "%s\n", values[i].xpath);
    			} else {
    				fprintf(stream, "\n%s\n", values[i].xpath);
    			}
    			break;
    		case SR_CONTAINER_T:
    			/* ignore */
    			break;
    		default:
    			if (strstr(values[i].xpath, "/name") != NULL) {
    			} else if (strstr(values[i].xpath, "/id") != NULL) {
    			} else if (strstr(values[i].xpath, "/num") != NULL) {
    			} else if (strstr(values[i].xpath, "/black-list") != NULL) {
    			} else if (strstr(values[i].xpath, "/terminate") != NULL) {
    			} else if (strstr(values[i].xpath, "/user") != NULL) {
    			} else if (strstr(values[i].xpath, "/program") != NULL) {
    			} else if (strstr(values[i].xpath, "/proto") != NULL) {
    				proto = *((uint8_t*)&values[i].data);
    				sr_print_val_stream(stream, &values[i]);
    			} else if (strstr(values[i].xpath, "/srcport") != NULL && (proto != 6) && (proto != 17)) {
    			} else if (strstr(values[i].xpath, "/dstport") != NULL && (proto != 6) && (proto != 17)) {
    				/* srcport and dstport are only valid for proto 6/17 */
    			} else if ((strstr(values[i].xpath, "/action") != NULL) && (strstr(values[i].xpath, "allow") != NULL)) {
    				/* do not print "action = allow" when "name = allow" */
    			} else {
    				sr_print_val_stream(stream, &values[i]);
    			}
    			break;
    		}
    	}
    	sr_free_values(values, count);

    	if (c == 's' || c == 'c') {
    		fclose(stream);
    	}
    } else if (c != '\n') {

    	/* wrong key pressed - let user know the options */
    	fprintf(stdout, "Options:\n"
    			"'p':\tprint rules set\n"
    			"'c':\tcreate new configuration file\n"
    			"\tworks only if configuration file does not exist\n"
    			"'s':\tsave current configuration file as %s/%s\n"
    			"\tif file already exist it will be overwritten\n"
    			"Press the desired option key:\n",
				CONFIG_DIR, OLD_CONFIG_FILE);
    }
}

/***********************************************************************
 * function:    main
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
int main(int argc, char **argv)
{
    sr_conn_ctx_t *conn = NULL;
    sr_session_ctx_t *sess = NULL;
    int rc = SR_ERR_OK;
    pthread_t thread_id;
    char curr_version[MAX_STR_SIZE]="", new_version[MAX_STR_SIZE]="";
    int opt, i;
    bool remote = false;
    fd_set rfds;

    snprintf(config_dir, MAX_STR_SIZE, "%s", CONFIG_DIR);

    while ((opt = getopt(argc, argv, "lhbs:c:d:")) != -1) {
        switch (opt) {
        case 'l':
            remote = false;
            break;
        case 'h':
            fprintf(stderr, "Usage: %s [-b background] [-d debug_level 0/1/2/3] [-c config directory. /etc/vsentry default] [-l (local use, default)] [-s (remote server address)]\n", argv[0]);
            exit(0);
        case 's':
            set_server_address(optarg);
            remote = true;
            break;
        case 'c':
            snprintf(config_dir, MAX_STR_SIZE, "%s", optarg);
            break;
        case 'b':
            background = 1;
            break;
        case 'd':
            if ((atoi(optarg) >= LEVEL_NONE) && (atoi(optarg)<=LEVEL_DEBUG))
                debug_level = atoi(optarg);
            break;
        default:
            break;
        }
    }

    if (background && (daemon(0, 0) < 0)) {
        fprintf(stderr, "failed to run in background, exiting ...\n");
        exit(-1);
    }

    updatem_debug("configuration directory: %s\n", config_dir);

    /* this pipe is used to signal the thread we need to exit */
    rc = pipe(pipe_fds);
    if (rc < 0){
        updatem_error("pipe failed %s\n", strerror(rc));
        exit(1);
    }

    signal(SIGINT, sigint_handler);

    /* init the sysrepo log level */
    sr_log_stderr(SR_LL_NONE/*SR_LL_DBG/SR_LL_WRN*/);

    /* connect to sysrepo */
    rc = sr_connect("update_manager", SR_CONN_DEFAULT, &conn);
    if (SR_ERR_OK != rc) {
        updatem_error("sr_connect failed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* start sysrepo session */
    rc = sr_session_start(conn, SR_DS_RUNNING, SR_SESS_DEFAULT, &sess);
    if (SR_ERR_OK != rc) {
        updatem_error("sr_session_start failed: %s\n", sr_strerror(rc));
        goto cleanup;
    }

    /* read current known security policy and push it to sysrepo */
    update_policy(sess);

    if (!remote) {
        /* start monitoring the config file */
        rc = pthread_create(&thread_id, NULL, &monitor_file, sess);
        if (rc != 0) {
            updatem_error("pthread_create: %s\n", strerror(errno));
            goto cleanup;
        }

        while (true) {
            /* watch for stdin/exit signal on pipe forever */
            FD_ZERO(&rfds);
            FD_SET(pipe_fds[0], &rfds);
            if (!background)
                FD_SET(fileno(stdin), &rfds);

            if (select((pipe_fds[0]+1), &rfds, NULL, NULL, NULL) > 0) {
                if (FD_ISSET(fileno(stdin), &rfds)) {
                    local_sr_print(sess);
                } else {
                    /* exit signal */
                    updatem_debug("main loop exit\n");
                    break;
                }
            }
        }
    } else {
        struct stat log_file_stat;
        struct timeval timeout;

        /* init the logging files */
        for (i = 0; i < MAX_LOG_FILE_NUM; i++) {
            log_files[i] = malloc(MAX_STR_SIZE);
            full_log_files[i] = malloc(MAX_STR_SIZE);
            if (i == 0) {
                snprintf(log_files[i], MAX_STR_SIZE, "%s", LOG_FILE);
                snprintf(full_log_files[i], MAX_STR_SIZE, "%s/%s", LOG_DIR, LOG_FILE);
            } else {
                snprintf(log_files[i], MAX_STR_SIZE, "%s.%d", LOG_FILE, i);
                snprintf(full_log_files[i], MAX_STR_SIZE, "%s/%s.%d", LOG_DIR, LOG_FILE, i);
            }
        }
        tracked_file_index = 0;
        updatem_debug("reading logs from %s\n", log_files[0]);

        /* init libcurl */
        remote_update_init();

        /* set the last timestamp we considered as the last log uplod was */
        gettimeofday(&last_upload, NULL);

        /* get the current file offset */
        if (stat(full_log_files[0], &log_file_stat)) {
            updatem_error("stat: %s\n", strerror(errno));
            goto cleanup;
        }
        file_offset = log_file_stat.st_size;

        /* start monitor the log files */
        rc = pthread_create(&thread_id, NULL, &monitor_file, NULL);
        if (rc != 0) {
            updatem_error("pthread_create: %s\n", strerror(errno));
            goto cleanup;
        }

        /* get the last known policy version number localy */
        get_set_current_version(false, curr_version);

        timeout.tv_sec = UPDATE_VER_INTERVAL;
        timeout.tv_usec = 0;

        while (true) {
            /* check for new version on server */
            memset(new_version, 0, sizeof(new_version));
            if (get_remote_version(new_version) == 0) {
                if ((strlen(new_version) > 0) && (strncmp(curr_version, new_version, strlen(new_version)) != 0)) {
                    updatem_debug("update available ... new ver %s\n", new_version);
                    if (!download_latest_policy(new_version, config_dir)) {
                        update_policy(sess);
                        get_set_current_version(true, new_version);
                        memset(curr_version, 0, sizeof(curr_version));
                        snprintf(curr_version, MAX_STR_SIZE, "%s", new_version);
                    }
                }
            }

            /* watch for exit signal on pipe */
            FD_ZERO(&rfds);
            FD_SET(pipe_fds[0], &rfds);

            if (select((pipe_fds[0]+1), &rfds, NULL, NULL, &timeout) == 0)
                continue;

            updatem_debug("main loop exit\n");
            break;
        }
    }

    pthread_join(thread_id, NULL);
    if (remote)
        remote_update_deinit();

cleanup:
    if (NULL != sess) {
        sr_session_stop(sess);
    }
    if (NULL != conn) {
        sr_disconnect(conn);
    }
    return rc;
}

int get_debug_level(void)
{
    return debug_level;
}

