#include <stdio.h>
#include <assert.h>
#include <arpa/inet.h>

#include <rte_memzone.h>
#include <rte_mempool.h>
#include <rte_malloc.h>

#include "parser/parser.h"
#include "parser/flow_cmdline.h"
#include "fw_conf/fw_conf.h"
#include "fw_conf/security_policy_conf.h"

#define SEC_POLICY_ZONE_NAME      "security policy conf"
#define SEC_POLICY_RULE_MP_NAME   "security policy rules"
#define SEC_POLICY_RULE_MP_SIZE   8192

static uint32_t sec_policy_dir;
static uint32_t rule_id;

static void sec_policy_in_handler(vector_t tokens)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *pos;
    secpolicy_rule_s *n;

    vrf_conf = fw_conf_get_vrf(fw_parse_vrf);
    if (!vrf_conf) {
        return;
    }

    conf = &vrf_conf->secpolicy_conf;

    security_policy_write_lock(fw_parse_vrf, 1);
    /* empty list */
    list_for_each_entry_safe(pos, n, &conf->head_in, list) {
        list_del(&pos->list);
        rte_mempool_put(conf->mp, pos);
    }
    security_policy_write_unlock(fw_parse_vrf, 1);

    sec_policy_dir = 1;

    return;
}

static void sec_policy_out_handler(vector_t tokens)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *pos;
    secpolicy_rule_s *n;

    vrf_conf = fw_conf_get_vrf(fw_parse_vrf);
    if (!vrf_conf) {
        return;
    }

    conf = &vrf_conf->secpolicy_conf;

    security_policy_write_lock(fw_parse_vrf, 0);
    /* empty list */
    list_for_each_entry_safe(pos, n, &conf->head_out, list) {
        list_del(&pos->list);
        rte_mempool_put(conf->mp, pos);
    }
    security_policy_write_unlock(fw_parse_vrf, 0);

    sec_policy_dir = 0;

    return;
}

int security_policy_rule_modify_status(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t status)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }
    if (rule) {
        rule->status = status;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_action(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t action)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->action = action;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_service(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t service)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->service = service;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_dst_ip(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *dst_ip)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->dst_ip = *dst_ip;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_dst_ip6(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *dst_ip6)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->dst_ip6 = *dst_ip6;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_src_ip(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *src_ip)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->src_ip = *src_ip;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_src_ip6(uint32_t vrf, uint32_t inbound, uint32_t id, cidr_st *src_ip6)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->src_ip6 = *src_ip6;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_src_port(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t port_min, uint32_t port_max)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->src_min_port = port_min;
        rule->src_max_port = port_max;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify_dst_port(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t port_min, uint32_t port_max)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule = NULL, *tmp;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_reverse(tmp, head, list) {
        if (tmp->id == id) {
            rule = tmp;
            break;
        }
    }

    if (rule) {
        rule->dst_min_port = port_min;
        rule->dst_max_port = port_max;
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}



static void rule_handler(vector_t tokens)
{
    char *str = set_value(tokens);

    rule_id = atoi(str);

    security_policy_rule_create(fw_parse_vrf, sec_policy_dir, rule_id);

    FREE_PTR(str);

    return;
}

static void status_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t status;

    if (0 == strncmp(str, "enable", strlen("enable"))) {
        status = 1;
    } else {
        status = 0;
    }

    security_policy_rule_modify_status(fw_parse_vrf, sec_policy_dir, rule_id, status);

    FREE_PTR(str);

    return;
}

static void action_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t action;

    if (0 == strncmp(str, "drop", strlen("drop"))) {
        action = 1;
    } else {
        action = 0;
    }

    security_policy_rule_modify_action(fw_parse_vrf, sec_policy_dir, rule_id, action);

    FREE_PTR(str);

    return;
}

static void service_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t service = 0;

    if (0 == strncmp(str, "tcp", strlen("tcp"))) {
        service = 1;
    }

    if (0 == strncmp(str, "udp", strlen("udp"))) {
        service = 2;
    }

    if (0 == strncmp(str, "icmp", strlen("icmp"))) {
        service = 3;
    }

    security_policy_rule_modify_service(fw_parse_vrf, sec_policy_dir, rule_id, service);

    FREE_PTR(str);

    return;
}

static void dst_ip_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    
    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET, str, &ip.addr.ip4);
        ip.prefixlen = atoi(++pos);
        security_policy_rule_modify_dst_ip(fw_parse_vrf, sec_policy_dir, rule_id, &ip);
    }

    FREE_PTR(str);

    return;
}

static void src_ip_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    
    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET, str, &ip.addr.ip4);
        ip.prefixlen = atoi(++pos);
        security_policy_rule_modify_src_ip(fw_parse_vrf, sec_policy_dir, rule_id, &ip);
    }

    FREE_PTR(str);

    return;
}

static void dst_ip6_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    
    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET6, str, &ip.addr.ip6);
        ip.prefixlen = atoi(++pos);
        security_policy_rule_modify_dst_ip6(fw_parse_vrf, sec_policy_dir, rule_id, &ip);
    }

    FREE_PTR(str);

    return;
}

static void src_ip6_handler(vector_t tokens)
{
    cidr_st ip = {0};
    char *str = set_value(tokens);
    char *pos;
    
    pos = strchr(str, '/');
    if (pos) {
        *pos = 0;
        inet_pton(AF_INET6, str, &ip.addr.ip6);
        ip.prefixlen = atoi(++pos);
        security_policy_rule_modify_src_ip6(fw_parse_vrf, sec_policy_dir, rule_id, &ip);
    }

    FREE_PTR(str);

    return;
}


static void dst_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t port_min;
    uint32_t port_max;
    char *p;

    port_min = atoi(str);

    p = strchr(str, '-');
    if (p) {
        port_max = atoi(++p);
    } else {
        port_max = port_min;
    }

    security_policy_rule_modify_dst_port(fw_parse_vrf, sec_policy_dir, rule_id, port_min, port_max);

    FREE_PTR(str);

    return;
}

static void src_port_handler(vector_t tokens)
{
    char *str = set_value(tokens);
    uint32_t port_min;
    uint32_t port_max;
    char *p;

    port_min = atoi(str);

    p = strchr(str, '-');
    if (p) {
        port_max = atoi(++p);
    } else {
        port_max = port_min;
    }

    security_policy_rule_modify_src_port(fw_parse_vrf, sec_policy_dir, rule_id, port_min, port_max);

    FREE_PTR(str);

    return;
}

void install_security_policy_keywords(void)
{
    install_keyword("security_policy_in", sec_policy_in_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("rule", rule_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("status",   status_handler, KW_TYPE_NORMAL);
    install_keyword("action",   action_handler, KW_TYPE_NORMAL);
    install_keyword("service",  service_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip",   dst_ip_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip",   src_ip_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip6",  dst_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip6",  src_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("dst_port", dst_port_handler, KW_TYPE_NORMAL);
    install_keyword("src_port", src_port_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_sublevel_end();

    install_keyword("security_policy_out", sec_policy_out_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("rule", rule_handler, KW_TYPE_NORMAL);
    install_sublevel();
    install_keyword("status",   status_handler, KW_TYPE_NORMAL);
    install_keyword("action",   action_handler, KW_TYPE_NORMAL);
    install_keyword("service",  service_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip",   dst_ip_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip",   src_ip_handler, KW_TYPE_NORMAL);
    install_keyword("dst_ip6",  dst_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("src_ip6",  src_ip6_handler, KW_TYPE_NORMAL);
    install_keyword("dst_port", dst_port_handler, KW_TYPE_NORMAL);
    install_keyword("src_port", src_port_handler, KW_TYPE_NORMAL);
    install_sublevel_end();
    install_sublevel_end();


    return;
}

void security_policy_keyword_value_init(void)
{
    printf("%s\n", __func__);
}


int security_policy_rule_create(uint32_t vrf, uint32_t inbound, uint32_t id)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule;
    struct list_head *head;
    int ret;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    if (security_policy_rule_is_exist(vrf, inbound, id)) {
        security_policy_write_unlock(vrf, inbound);
        return 0;
    }

    ret = rte_mempool_get(conf->mp, (void **)&rule);
    if (ret < 0) {
        printf("security policy rule create failed.\n");
        security_policy_write_unlock(vrf, inbound);
        return -1;
    }

    memset(rule, 0, sizeof(secpolicy_rule_s));
    rule->id = id;

    list_add_tail(&rule->list, head);
    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_delete(uint32_t vrf, uint32_t inbound, uint32_t id)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *rule, *n;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);
    list_for_each_entry_safe(rule, n, head, list) {
        if (id == rule->id) {
            list_del(&rule->list);
            rte_mempool_put(conf->mp, rule);
            break;
        }
    }
    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_move(uint32_t vrf, uint32_t inbound, uint32_t id, uint32_t base_id, uint32_t action)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *item = NULL;
    secpolicy_rule_s *base = NULL;
    secpolicy_rule_s *tmp, *n;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_safe(tmp, n, head, list) {
        if (!item) {
            if (id == tmp->id) {
                item = tmp;
            }
        }

        if (!base) {
            if (base_id == tmp->id) {
                base = tmp;
            }
        }

        if (item && base) {
            break;
        }
    }

    if (item && base) {

        list_del(&item->list);

        if (action) {
            /* before */
            list_add_tail(&item->list, &base->list);
        } else {
            /* after */
            list_add(&item->list, &base->list);
        }
    }
    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_modify(uint32_t vrf, uint32_t inbound, secpolicy_rule_s *rule)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *tmp, *n;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (!security_policy_rule_is_exist(vrf, inbound, rule->id)) {
        return -1;
    }

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    security_policy_write_lock(vrf, inbound);

    list_for_each_entry_safe(tmp, n, head, list) {
        if (0 == tmp->id) {
            memcpy(tmp, rule, sizeof(secpolicy_rule_s));
            break;
        }
    }

    security_policy_write_unlock(vrf, inbound);

    return 0;
}

int security_policy_rule_get(uint32_t vrf, uint32_t inbound, uint32_t id, secpolicy_rule_s *rule)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *tmp, *n;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    if (list_empty(head)) {
        return -1;
    }

    list_for_each_entry_safe(tmp, n, head, list) {
        if (id == tmp->id) {
            memcpy(rule, tmp, sizeof(secpolicy_rule_s));
            return 0;
        }
    }

    return -1;
}

int security_policy_rule_is_exist(uint32_t vrf, uint32_t inbound, uint32_t id)
{
    fw_vrf_conf_s *vrf_conf;
    secpolicy_rule_s *rule, *n;
    security_policy_conf_s *conf;
    struct list_head *head;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    if (inbound) {
        head = &conf->head_in;
    } else {
        head = &conf->head_out;
    }

    if (list_empty(head)) {
        return 0;
    }

    list_for_each_entry_safe(rule, n, head, list) {
        if (id == rule->id) {
            return 1;
        }
    }

    return 0;
}

security_policy_conf_s *security_policy_conf_get(uint32_t vrf)
{
    fw_vrf_conf_s *vrf_conf;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return NULL;
    }

    return &vrf_conf->secpolicy_conf;
}

int security_policy_conf_init(uint32_t vrf)
{
    struct rte_mempool *mp;
    fw_conf_s *fw_conf;
    security_policy_conf_s *conf;

    fw_conf = fw_conf_get();
    if (!fw_conf || vrf >= FW_VRF_MAX_SIZE) {
        return -1;
    }

    mp = rte_mempool_lookup(SEC_POLICY_RULE_MP_NAME);
    if (!mp) {
        mp = rte_mempool_create(SEC_POLICY_RULE_MP_NAME, SEC_POLICY_RULE_MP_SIZE,
                sizeof(secpolicy_rule_s), 0, 0, NULL, NULL,
                NULL, NULL, SOCKET_ID_ANY, 0);
        if (!mp) {
            printf("security policy rules create mempool failed.\n");
            return -1;
        }
    }

    /* init */
    conf = &fw_conf->vrf_conf[vrf].secpolicy_conf;
    INIT_LIST_HEAD(&conf->head_in);
    rte_rwlock_init(&conf->rwlock_in);
    INIT_LIST_HEAD(&conf->head_out);
    rte_rwlock_init(&conf->rwlock_out);
    conf->mp = mp;

    return 0;
}

int security_policy_conf_term(uint32_t vrf)
{
    fw_vrf_conf_s *vrf_conf;
    security_policy_conf_s *conf;
    secpolicy_rule_s *pos;
    secpolicy_rule_s *n;

    vrf_conf = fw_conf_get_vrf(vrf);
    if (!vrf_conf) {
        return -1;
    }

    conf = &vrf_conf->secpolicy_conf;

    /* free all rules */
    list_for_each_entry_safe(pos, n, &conf->head_in, list) {
        list_del(&pos->list);
        rte_mempool_put(conf->mp, pos);
    }

    list_for_each_entry_safe(pos, n, &conf->head_out, list) {
        list_del(&pos->list);
        rte_mempool_put(conf->mp, pos);
    }

    if (conf->mp) {
        rte_mempool_free(conf->mp);
    }

    return 0;
}

