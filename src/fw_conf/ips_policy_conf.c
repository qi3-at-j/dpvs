#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>
#include<sys/un.h>
#include<unistd.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/ips_policy_conf.h"
#include "fw_conf/ips_policy_cli.h"

#define BUFFER_SIZE 1024

static uint32_t ips_rule_id;

static void ips_policy_in_handler(vector_t tokens)
{
    return;
}

static void ips_rule_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    ips_rule_id = atoi(str);

    FREE_PTR(str);

    return;
}

static void ips_action_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    /*uint32_t action;*/

    /*if (0 == strncmp(str, "drop", strlen("drop"))) {
        action = 1;
    } else {
        action = 0;
    }*/

    RTE_LOG(INFO, CFG_FILE, "%s: %d %s\n", __func__, ips_rule_id, str);

    ips_policy_set_action(fw_parse_vrf, ips_rule_id, str);

    FREE_PTR(str);

    return;
}

static void dpi_cfg_in_handler(vector_t tokens)
{
    return;
}

static void dpi_vpatch_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: vrf %d %s\n", __func__, fw_parse_vrf, str);

    if (0 == strcmp(str, "on")) {
        dpi_set_vpatch_switch(fw_parse_vrf, "on");
    }

    if (0 == strcmp(str, "off")) {
        dpi_set_vpatch_switch(fw_parse_vrf, "off");
    }

    FREE_PTR(str);

    return;
}

static void dpi_runmode_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    RTE_LOG(INFO, CFG_FILE, "%s: vrf %d %s\n", __func__, fw_parse_vrf, str);

    if (0 == strcmp(str, "block")) {
        dpi_set_mode(fw_parse_vrf, "block");
    }

    if (0 == strcmp(str, "monitor")) {
        dpi_set_mode(fw_parse_vrf, "monitor");
    }


    FREE_PTR(str);

    return;
}

static int ips_set_rule_action(uint32_t vrf_id, uint32_t rule_id, char *new_action)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int ret = 0, len = 0;
    
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);
    
    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"set-sig-action\",\"arguments\":{\"action\":\"%s\",\"ruleid\":%u,\"vrfid\":%u}}",
        new_action, rule_id, vrf_id);
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);
    
    close(sock_fd);

    return 0;
}

int ips_policy_set_action(uint32_t vrf, uint32_t rule_id, char *action)
{
    fw_vrf_conf_s *fw_conf;
    int ret = 0;

    fw_conf = fw_conf_get_vrf(vrf);
    if (!fw_conf) {
        /* vrf not exist */
        return -1;
    }

    ret = ips_set_rule_action(vrf, rule_id, action);
    if (ret != 0) {
        printf("ips modify rule action failed\n");
        return -1;
    }

    return 0;
}

static int ips_get_rule_action(uint32_t vrf_id, uint32_t rule_id)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int ret = 0, len = 0;
    int action = -1;
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);
    
    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"get-sig-action\",\"arguments\":{\"ruleid\":%u,\"vrfid\":%u}}",
        rule_id, vrf_id);
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    if (strstr(buffer, "\"action\":\"drop\"") != NULL)
    {
        action = ACTION_DROP;
    }
    else if (strstr(buffer, "\"action\":\"alert\"") != NULL)
    {
        action = ACTION_ALERT;
    }
    else if (strstr(buffer, "\"action\":\"pass\"") != NULL)
    {
        action = ACTION_PASS;
    }

    close(sock_fd);

    return action;
}

int ips_policy_get_action(uint32_t vrf, uint32_t rule_id)
{
    fw_vrf_conf_s *fw_conf;

    fw_conf = fw_conf_get_vrf(vrf);
    if (!fw_conf) {
        /* vrf not exist */
        return -1;
    }

    return ips_get_rule_action(vrf, rule_id);
}

static int _dpi_set_mode(uint32_t vrf_id, char *mode)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int ret = 0, len = 0;
    
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);
    
    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"set-dpi-mode\",\"arguments\":{\"mode\":\"%s\",\"vrfid\":%u}}",
        mode, vrf_id);
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);
    
    close(sock_fd);

    return 0;
}

int dpi_set_mode(uint32_t vrf, char *mode)
{
    fw_vrf_conf_s *fw_conf;
    int ret = 0;

    fw_conf = fw_conf_get_vrf(vrf);
    if (!fw_conf) {
        /* vrf not exist */
        return -1;
    }

    ret = _dpi_set_mode(vrf, mode);
    if (ret != 0) {
        printf("set dpi mode failed\n");
        return -1;
    }

    return 0;
}

static int _dpi_get_mode(uint32_t vrf_id)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int ret = 0, len = 0;
    int mode = -1;
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);
    
    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"get-dpi-mode\",\"arguments\":{\"vrfid\":%u}}",
        vrf_id);
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);
    if (strstr(buffer, "\"mode\":\"monitor\"") != NULL)
    {
        mode = DPI_MODE_MONITOR;
    }
    else if (strstr(buffer, "\"mode\":\"block\"") != NULL)
    {
        mode = DPI_MODE_BLOCK;
    }

    close(sock_fd);

    return mode;
}

int dpi_get_mode(uint32_t vrf)
{
    int mode;
    fw_vrf_conf_s *fw_conf;

    fw_conf = fw_conf_get_vrf(vrf);
    if (!fw_conf) {
        /* vrf not exist */
        return -1;
    }

    mode = _dpi_get_mode(vrf);
    return mode;
}

static int _dpi_set_vpatch_switch(uint32_t vrf_id, char *vpatch)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int ret = 0, len = 0;
    
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);
    
    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"set-vpatch-switch\",\"arguments\":{\"vpatch\":\"%s\",\"vrfid\":%u}}",
        vpatch, vrf_id);
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);
    
    close(sock_fd);

    return 0;
}

int dpi_set_vpatch_switch(uint32_t vrf, char *vpatch)
{
    fw_vrf_conf_s *fw_conf;
    int ret = 0;

    fw_conf = fw_conf_get_vrf(vrf);
    if (!fw_conf) {
        /* vrf not exist */
        return -1;
    }

    ret = _dpi_set_vpatch_switch(vrf, vpatch);
    if (ret != 0) {
        printf("set vpatch switch failed\n");
        return -1;
    }

    return 0;
}

static int _dpi_get_vpatch_switch(uint32_t vrf_id)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int vpatch = -1;
    int ret = 0, len = 0;
    
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);
    
    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"get-vpatch-switch\",\"arguments\":{\"vrfid\":%u}}",
        vrf_id);
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    if (strstr(buffer, "\"vpatch\":\"off\"") != NULL)
    {
        vpatch = VPATCH_OFF;
    }
    else if (strstr(buffer, "\"vpatch\":\"on\"") != NULL)
    {
        vpatch = VPATCH_ON;
    }
    close(sock_fd);

    return vpatch;
}


int dpi_get_vpatch_switch(uint32_t vrf)
{
    fw_vrf_conf_s *fw_conf;
    int vpatch;
    fw_conf = fw_conf_get_vrf(vrf);
    if (!fw_conf) {
        /* vrf not exist */
        return -1;
    }

    vpatch = _dpi_get_vpatch_switch(vrf);
    return vpatch;
}

static int _dpi_set_trace_switch(uint32_t module_id, uint32_t trace_switch)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    int ret = 0, len = 0;
    
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);
    
    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"set-trace\",\"arguments\":{\"trace_switch\":%u,\"module_id\":%u}}",
        trace_switch, module_id);
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);
    
    close(sock_fd);

    return 0;
}

int dpi_set_trace_switch(uint32_t module, uint32_t trace_switch)
{
    int ret = _dpi_set_trace_switch(module, trace_switch);
    if (ret != 0) {
        printf("set trace switch failed\n");
        return -1;
    }

    return 0;
}

static int _dpi_get_trace_switch(void)
{
    struct sockaddr_un un;
    int sock_fd;
    char buffer[BUFFER_SIZE];
    char *pModule = NULL;
    int uiModule = 0;
    int ret = 0, len = 0;
    
    un.sun_family = AF_UNIX;
    strcpy(un.sun_path, IPS_SOCKET_FILE);

    sock_fd = socket(AF_UNIX,SOCK_STREAM,0);
    if (sock_fd < 0) {
        printf("Request socket failed\n");
        return -1;
    }

    if (connect(sock_fd,(struct sockaddr *)&un,sizeof(un)) < 0) {
        close(sock_fd);
        printf("connect socket failed\n");
        return -1;
    }

    /* init */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), "{\"version\":\"0.1\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init send error");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("init recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    /* send cmd */
    memset(buffer, 0, sizeof(buffer));
    len = snprintf(buffer, sizeof(buffer), 
        "{\"command\":\"get-trace\"}");
    printf("SEND:%s\n", buffer);
    ret = send(sock_fd, buffer, len, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd send error:");
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    ret = recv(sock_fd, buffer, BUFFER_SIZE, 0);
    if (ret < 0) {
        close(sock_fd);
        perror("cmd recv error:");
        return -1;
    }
    printf("RECV:%s\n", buffer);

    pModule = strstr(buffer, "\"module\":");
    if ((pModule != NULL) && (strlen(pModule) > 9))
    {
        uiModule = atoi(pModule + 9);
    }

    close(sock_fd);

    return uiModule;
}


int dpi_get_trace_switch(void)
{
    int module = _dpi_get_trace_switch();
    return module;
}

void install_ips_policy_keywords(void)
{
    install_keyword("dpi_cfg", dpi_cfg_in_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("vpatch", dpi_vpatch_handler, KW_TYPE_NORMAL);
    install_keyword("runmode", dpi_runmode_handler, KW_TYPE_NORMAL);
    install_sublevel_end();

    install_keyword("ips_policy", ips_policy_in_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("rule", ips_rule_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("action", ips_action_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_sublevel_end();

    return;
}

void ips_policy_keyword_value_init(void)
{
    //printf("%s\n", __func__);
    return;
}

int ips_policy_conf_init(uint32_t vrf)
{
    return 0;
}

int ips_policy_conf_term(uint32_t vrf)
{
    return 0;
}

