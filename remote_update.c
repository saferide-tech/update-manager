#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <curl/curl.h>
#include <errno.h>
#include "update_manager.h"

char server[MAX_STR_SIZE] = "http://example.com";
char vin[MAX_STR_SIZE]  = DEMO_VIN;

/***********************************************************************
 * function:    remote_update_init
 * description: init the remote module (curl)
 * in param:    n/a
 * return:      n/a
 **********************************************************************/
void remote_update_init(void)
{
    FILE *vin_file;

    curl_global_init(CURL_GLOBAL_DEFAULT);

    vin_file = fopen(DEMO_VIN_FILE, "r");
    if (vin_file == NULL) {
        updatem_warn("fopen %s failed: %s\n", DEMO_VIN_FILE, strerror(errno));
        return;
    }

    if (fgets(vin, MAX_STR_SIZE, vin_file))
        updatem_debug("VIN is %s\n", vin);

    fclose(vin_file);
}

/***********************************************************************
 * function:    remote_update_deinit
 * description: deinit the remote module (curl)
 * in param:    n/a
 * return:      n/a
 **********************************************************************/
void remote_update_deinit(void)
{
    curl_global_cleanup();
}

/***********************************************************************
 * function:    get_ver_cb
 * description: this function is set as the write callback.
 *              it will copy the contents to userp
 * in param:    
 * return:      
 **********************************************************************/
static size_t get_ver_cb(void *contents, size_t size, size_t nmemb, void *userp)
{
    char *version = (char*)userp;
    char *nl;

    strncpy(version, contents, (size * nmemb));
    /* clear new-line */
    nl = strchr(version, '\n');
    if (nl)
        *nl = 0;

    return (size * nmemb);
}

/***********************************************************************
 * function:    get_remote_version
 * description: read the security policy version from remote server
 *              and copy it to version
 * in param:    char *version
 * return:      n/a
 **********************************************************************/
int get_remote_version(char *version)
{
    CURL *curl_handle;
    CURLcode res;
    char version_url[MAX_STR_SIZE];
    int ret = 0;

    snprintf(version_url, MAX_STR_SIZE, "https://%s/version.txt", server);

    curl_handle = curl_easy_init();
    if (!curl_handle) {
        updatem_error("curl_easy_init failed\n");
        return -1;
    }

    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl_handle, CURLOPT_URL, version_url);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, get_ver_cb);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)version);

    res = curl_easy_perform(curl_handle);
    if(res != CURLE_OK) {
        updatem_error("curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        ret = -1;
    }

    curl_easy_cleanup(curl_handle);

    return ret;
}

/***********************************************************************
 * function:    download_policy_cb
 * description: this function is set as the write callback.
 *              it will write the received data to a file pass by stream
 * in param:    
 * return:      
 **********************************************************************/
static size_t download_policy_cb(void *contents, size_t size, size_t nmemb, void *stream)
{
    size_t written = fwrite(contents, 1, (size*nmemb), (FILE *)stream);

    return written;
}

/***********************************************************************
 * function:    download_latest_policy
 * description: downlaod a security policy file from the remote server.
 * in param:    char *new_version
 * return:      
 **********************************************************************/
int download_latest_policy(char *new_version, char *config_dir)
{
    CURL *curl_handle;
    FILE *tmp_config_file;
    char remote_file_url[MAX_STR_SIZE];
    CURLcode res;
    int ret = 0;
    char tmp_file[MAX_STR_SIZE];

    snprintf(tmp_file, MAX_STR_SIZE, "%s/%s", config_dir, TMP_FILE);
    snprintf(remote_file_url, MAX_STR_SIZE,
        "https://%s/sec_policy_%s.xsp", server, new_version);

    updatem_debug("downloading remote file %s\n", remote_file_url);

    curl_handle = curl_easy_init();
    if (!curl_handle) {
        updatem_error("curl_easy_init failed\n");
        ret = -1;
        goto out;
    }

    curl_easy_setopt(curl_handle, CURLOPT_NOSIGNAL, 1);
    curl_easy_setopt(curl_handle, CURLOPT_URL, remote_file_url);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
    curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_NOPROGRESS, 1L);
    curl_easy_setopt(curl_handle, CURLOPT_TIMEOUT, 5L);
    curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, download_policy_cb);

    /* open the file */
    tmp_config_file = fopen(tmp_file, "wb+");
    if(tmp_config_file) {
        curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, tmp_config_file);
        res = curl_easy_perform(curl_handle);
        if(res != CURLE_OK) {
            updatem_error("curl_easy_perform failed: %s\n", curl_easy_strerror(res));
            ret = -1;
        } else {
            char config_file_full[MAX_STR_SIZE];

            snprintf(config_file_full, MAX_STR_SIZE, "%s/%s", config_dir, CONFIG_FILE);
            /* copy tmp to real config file */
            if (rename(tmp_file, config_file_full)) {
                updatem_error("failed to rename %s to %s: %s\n", TMP_FILE,
                    config_file_full, strerror(errno));
                ret = -1;
            }
        }
    } else {
        updatem_error("failed to open tmp file: %s\n", strerror(errno));
        ret = -1;
    }

    if (tmp_config_file)
        fclose(tmp_config_file);

    curl_easy_cleanup(curl_handle);

out:
    return ret;
}

CURL *upload_curl_handle = NULL;

struct file_state{
    FILE *file;
    size_t write_size;
};

/***********************************************************************
 * function:    read_callback
 * description: used as callback to read from the log file
 * in param:    
 * return:      
 **********************************************************************/
size_t read_callback(char *buffer, size_t size, size_t nitems, void *userp)
{
    struct file_state *ptr = (struct file_state*)userp;
    size_t written = 0;
    size_t actual_size = ptr->write_size;

    //updatem_debug("ptr->write_size %lu\n", ptr->write_size);

    if (ptr->write_size == 0)
        return 0;

    if ((size*nitems) < actual_size)
        actual_size = (size*nitems);

    //updatem_debug("actual_size %lu size %lu nitems %lu\n", actual_size, size, nitems);

    written = fread(buffer, 1, actual_size, ptr->file);

    //updatem_debug("written %lu\n", written);

    ptr->write_size -= written;

    return written;
}

/***********************************************************************
 * function:    upload_log_file
 * description: upload to the remote server a portion of a log file.
 * in param:    char* filename
 *              int offset
 * return:      size of uploaded data
 **********************************************************************/
int upload_log_file(char* filename, int offset)
{
    FILE* logfile = NULL;
    char post_vin[MAX_STR_SIZE];
    CURLcode res;
    struct stat logfile_stat;
    int ret = 0, size;
    struct curl_httppost *formpost = NULL;
    struct curl_httppost *lastptr = NULL;
    struct curl_slist *chunk = NULL;
    struct file_state log_file_state;
    char post_url[MAX_STR_SIZE];

    if (!upload_curl_handle) {
        upload_curl_handle = curl_easy_init();
        if (!upload_curl_handle) {
            updatem_error("curl_easy_init failed\n");
            goto out;
        }
        snprintf(post_url, MAX_STR_SIZE, "https://%s/logs/post.php", server);
        curl_easy_setopt(upload_curl_handle, CURLOPT_URL, post_url);
        curl_easy_setopt(upload_curl_handle, CURLOPT_NOSIGNAL, 1);
        curl_easy_setopt(upload_curl_handle, CURLOPT_SSL_VERIFYPEER, 0L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_SSL_VERIFYHOST, 0L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_FAILONERROR, 1L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_NOPROGRESS, 1L);
        curl_easy_setopt(upload_curl_handle, CURLOPT_TIMEOUT, 5L);
        //curl_easy_setopt(upload_curl_handle, CURLOPT_VERBOSE, 1L);
        snprintf(post_vin, MAX_STR_SIZE, "X-VIN: %s", vin);
        chunk = curl_slist_append(chunk, post_vin);
        curl_easy_setopt(upload_curl_handle, CURLOPT_HTTPHEADER, chunk);
        curl_easy_setopt(upload_curl_handle, CURLOPT_READFUNCTION, read_callback);
    }

    logfile = fopen(filename, "rb");
    if (!logfile) {
        updatem_error("%s fopen failed: %s\n", filename, strerror(errno));
        goto out;
    }

    if (fstat(fileno(logfile), &logfile_stat)) {
        updatem_error("%s fstat failed: %s\n", filename, strerror(errno));
        goto out;
    }

    /* set the file offset in the last position we read from */
    if(fseek(logfile, offset, SEEK_SET) < 0) {
        updatem_error("%s fseek failed: %s\n", filename, strerror(errno));
        goto out;
    }

    size = (logfile_stat.st_size - offset);
    if (size <= 0) {
        updatem_error("something is wrong, size is %d\n", size);
        goto out;
    }

    log_file_state.write_size = size;
    log_file_state.file = logfile;

    //updatem_debug("uploading %d bytes\n", size);

    curl_formadd(&formpost, &lastptr, CURLFORM_COPYNAME, "logs",
        CURLFORM_FILENAME, filename, CURLFORM_STREAM, &log_file_state,
        CURLFORM_CONTENTSLENGTH, size, CURLFORM_END);
    curl_easy_setopt(upload_curl_handle, CURLOPT_HTTPPOST, formpost);

    res = curl_easy_perform(upload_curl_handle);
    if(res != CURLE_OK) {
        updatem_error("curl_easy_perform failed: %s\n", curl_easy_strerror(res));
        goto out;
    }
    ret = size;

out:
    if (logfile)
        fclose(logfile);

    return ret;
}

/***********************************************************************
 * function:    
 * description: 
 * in param:    
 * return:      
 **********************************************************************/
void set_server_address(char* address)
{
    memset(server, 0, MAX_STR_SIZE);

    strncpy(server, address, MIN(MAX_STR_SIZE-1, strlen(address)));

    updatem_debug("server address was set to %s\n", server);
}
