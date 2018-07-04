/**
 * @brief  IpIp module for Nginx.
 *
 * @section LICENSE
 *
 * Copyright (C) 2018 by ipip.net
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
  */
#include <stdio.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef unsigned char byte;
typedef unsigned int uint;
#define B2IL(b) (((b)[0] & 0xFF) | (((b)[1] << 8) & 0xFF00) | (((b)[2] << 16) & 0xFF0000) | (((b)[3] << 24) & 0xFF000000))
#define B2IU(b) (((b)[3] & 0xFF) | (((b)[2] << 8) & 0xFF00) | (((b)[1] << 16) & 0xFF0000) | (((b)[0] << 24) & 0xFF000000))

struct DBContext {
    byte *data;
    byte *index;
    uint *flag;
    uint offset;
} ;
typedef struct {
    ngx_str_t  db_name;
    struct DBContext   *db_ctx;
    ngx_http_complex_value_t ip_source;

    time_t                   last_check;
    time_t                   last_change;
    time_t                   check_interval;
} ngx_http_ipip_conf_t;

char *strtok_r_2(char *str, char const *delims, char **context) {
    char *p = NULL, *ret = NULL;

    if (str != NULL) {
        *context = str;
    }

    if (*context == NULL) {
        return NULL;
    }

    if ((p = strpbrk(*context, delims)) != NULL) {
        *p = 0;
        ret = *context;
        *context = ++p;
    }
    else if (**context) {
        ret = *context;
        *context = NULL;
    }
    return ret;
}

static struct DBContext* init_db(const char* ipdb, int* error_code, ngx_conf_t *cf);
static ngx_int_t ngx_http_ipip_reload_db(ngx_http_ipip_conf_t  *icf);
static int destroy(struct DBContext* ctx);
static ngx_int_t find_result_by_ip(const struct DBContext* ctx,const char *ip, char *result);
static ngx_int_t ngx_http_ipip_addr_str(ngx_http_request_t *r, char* ipstr);

int destroy(struct DBContext* ctx) {
    if (ctx->flag != NULL) {
        free(ctx->flag);
    }
    if (ctx->index != NULL) {
        free(ctx->index);
    }
    if (ctx->data != NULL) {
        free(ctx->data);
    }
    ctx->offset = 0;
    free(ctx);
    return 0;
}

struct DBContext* init_db(const char* ipdb, int* error_code, ngx_conf_t *cf) {
    int read_count = 0;
    int copy_bytes = 0;
    struct DBContext* ctx = (struct DBContext *)malloc(sizeof(struct DBContext));
    if (ctx == NULL) {
        (*error_code) = 1;
        return NULL;
    }
    ctx->data = NULL;
    ctx->index = NULL;
    ctx->flag = NULL;
    ctx->offset = 0;

    FILE *file = fopen(ipdb, "rb");
    if (file == NULL) {
        (*error_code) = 2;
        free(ctx);
        return NULL;
    }
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    ctx->data = (byte *) malloc(size * sizeof(byte));
    read_count = fread(ctx->data, sizeof(byte), (size_t) size, file);
    if (read_count <= 0) {
        (*error_code) = 3;
        free(ctx->data);
        free(ctx);
        return NULL;
    }
    //ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "total read %d bytes data", read_count);
    
    fclose(file);
    
    uint indexLength = B2IU(ctx->data);

    //ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "index len = %d", indexLength);
    
    ctx->index = (byte *) malloc(indexLength * sizeof(byte));
    if (ctx->index == NULL) {
        (*error_code) = 4;
        free(ctx->data);
        free(ctx);
        return NULL;
    }
    if (indexLength > size - 4) {
        copy_bytes = size - 4;
    } else {
        copy_bytes = indexLength;
    }

    ngx_memcpy(ctx->index, ctx->data + 4, copy_bytes);
    
    ctx->offset = indexLength;
    
    int flag_bytes = 65536 * sizeof(uint);
    ctx->flag = (uint *) malloc(flag_bytes);
    if (copy_bytes > flag_bytes) {
        copy_bytes = flag_bytes;
    }
    //ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0, "copy %d bytes from index to flag", copy_bytes);
    ngx_memcpy(ctx->flag, ctx->index, copy_bytes);
    
    return ctx;
}

static ngx_int_t find_result_by_ip(const struct DBContext* ctx, const char *ip, char *result) {
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    uint ips[4];
    int num = sscanf(ip, "%d.%d.%d.%d", &ips[0], &ips[1], &ips[2], &ips[3]);
    if (num == 4) {
        uint ip_prefix_value = ips[0] * 256 + ips[1];
        uint ip2long_value = B2IU(ips);
        uint start = ctx->flag[ip_prefix_value];
        uint max_comp_len = ctx->offset - 262144 - 4;
        uint index_offset = 0;
        uint index_length = 0;

        //uint begin = start * 9 + 262144;
        uint end = max_comp_len;
        uint low = start * 9 + 262144;
        uint high = end;
        while (low <= high) {
            uint mid = low + ((high - low) >> 1);
            mid = low + (uint)((mid - low) / 9) * 9;
            if (B2IU(ctx->index + mid) < ip2long_value) {
                low = mid + 9;
            } else {
                high = mid - 9;
            }
        }
        uint target = low;
        index_offset = B2IL(ctx->index + target + 4) & 0x00FFFFFF;
        index_length = (ctx->index[target+7] << 8) + ctx->index[target+8];
        //fprintf(stderr, "index length = %u\n", index_length);
        memcpy(result, ctx->data + ctx->offset + index_offset - 262144, index_length);
        result[index_length] = '\0';
    }
    return NGX_OK;
}

ngx_module_t ngx_http_ipip_module;

static ngx_int_t get_element(ngx_http_request_t *r, char* result, 
    ngx_http_ipip_conf_t* icf, int index) {
    struct DBContext *db_ctx = icf->db_ctx;
    int errorcode;
    char ipstr[32];
    ngx_str_t complex_ip_val;

    if (icf->ip_source.value.len > 0) {
        if (ngx_http_complex_value(r, &icf->ip_source, &complex_ip_val) != NGX_OK) {
            return NGX_ERROR;
        }
        complex_ip_val.data[complex_ip_val.len] = '\0';
    } else {
        ngx_http_ipip_addr_str(r, ipstr);
        complex_ip_val.len = ngx_strlen(ipstr);
        complex_ip_val.data = ngx_pnalloc(r->pool, complex_ip_val.len+1);
        ngx_memcpy(complex_ip_val.data, ipstr, complex_ip_val.len);
        complex_ip_val.data[complex_ip_val.len] = '\0';
    }

    char db_result[1024] = {"\0"};
    errorcode = find_result_by_ip(db_ctx, (const char*)complex_ip_val.data, db_result);
    if (errorcode != NGX_OK) {
        return errorcode;
    }

    char *rst = NULL;
    char *lasts = NULL;
    rst = strtok_r_2(db_result, "\t", &lasts);
    int cnt = 0;
    while (rst) {
        if (index == cnt) {
            size_t rlen = ngx_strlen(rst);
            ngx_memcpy(result, rst, rlen);
            result[rlen] = '\0';
            break;
        }
        rst = strtok_r_2(NULL, "\t", &lasts);
        ++ cnt;
    }
    if (cnt < index) {
        return NGX_ERROR;
    }

    return NGX_OK;
}

static ngx_int_t ngx_ipip_set_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, int index) {
    ngx_http_ipip_conf_t  *icf = ngx_http_get_module_main_conf(r, ngx_http_ipip_module);

    ngx_http_ipip_reload_db(icf);

    char result[256] = {"\0"};
    size_t val_len;

    int ret = get_element(r, result, icf, index);
    if (ret != NGX_OK) {
        return ret;
    }

    val_len = ngx_strlen(result);
    v->data = ngx_pnalloc(r->pool, val_len + 1);
    if (v->data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(v->data, result, val_len);
    v->data[val_len] = '\0';

    v->len = val_len;
    v->valid = 1;
    v->no_cacheable = 0;
    v->not_found = 0;

    return NGX_OK;
}

#define NGX_IPIP_COUNTRY_NAME_CODE     0
#define NGX_IPIP_REGION_NAME_COEE      1
#define NGX_IPIP_CITY_NAME_CODE        2
#define NGX_IPIP_OWNER_DOMAIN_CODE     3
#define NGX_IPIP_ISP_DOMAIN_CODE       4
#define NGX_IPIP_LATITUDE_CODE         5
#define NGX_IPIP_LONGITUDE_CODE        6
#define NGX_IPIP_TIMEZONE_CODE         7
#define NGX_IPIP_UTC_OFFSET_CODE       8
#define NGX_IPIP_CHINA_ADMIN_CODE      9
#define NGX_IPIP_IDD_CODE_CODE         10
#define NGX_IPIP_COUNTRY_CODE_CODE     11
#define NGX_IPIP_CONTINENT_CODE_CODE   12
#define NGX_IPIP_IDC_CODE              13
#define NGX_IPIP_BASE_STATION_CODE     14
#define NGX_IPIP_ANYCAST_CODE          15

static char *ngx_http_ipip_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_ipip_parse_ip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_ipip_add_parse_ip_variable(ngx_conf_t *cf, ngx_command_t *dummy, 
 void *conf);

static ngx_int_t ngx_http_ipip_add_variables(ngx_conf_t *cf);

static ngx_int_t ngx_http_ipip_country_variable(ngx_http_request_t *r, 
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_region_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_owner_domain_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_isp_domain_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_latitude_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_longitude_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_timezone_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ipip_utc_offset_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_china_admin_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_idd_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static ngx_int_t ngx_http_ipip_country_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_continent_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_idc_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_base_station_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);
static ngx_int_t ngx_http_ipip_anycast_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data);

static void *ngx_http_ipip_create_conf(ngx_conf_t *cf);
static void ngx_http_ipip_cleanup(void *data);
/**
 * This module provided directive: ipip.
 *
 */
static ngx_command_t ngx_http_ipip_commands[] = {

    { ngx_string("ipip_db"), /* directive */
      NGX_HTTP_MAIN_CONF|NGX_CONF_TAKE2, /* location context and takes*/
      ngx_http_ipip_db, /* configuration setup function */
      NGX_HTTP_MAIN_CONF_OFFSET, /* No offset. Only one context is supported. */
      0, /* No offset when storing the module configuration on struct. */
      NULL},
      { ngx_string("ipip_parse_ip"), /* directive */
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_HTTP_LOC_CONF | NGX_CONF_TAKE1,
      ngx_ipip_parse_ip, /* configuration setup function */
      NGX_HTTP_MAIN_CONF_OFFSET | NGX_HTTP_LOC_CONF_OFFSET | NGX_HTTP_SRV_CONF_OFFSET, /* No offset. Only one context is supported. */
      0, /* No offset when storing the module configuration on struct. */
      NULL},

    ngx_null_command /* command termination */
};

/* The module context. */
static ngx_http_module_t ngx_http_ipip_module_ctx = {
    ngx_http_ipip_add_variables, /* preconfiguration */
    NULL, /* postconfiguration */

    ngx_http_ipip_create_conf, /* create main configuration */
    NULL, /* init main configuration */

    NULL, /* create server configuration */
    NULL, /* merge server configuration */

    NULL, /* create location configuration */
    NULL /* merge location configuration */
};

/* Module definition. */
ngx_module_t ngx_http_ipip_module = {
    NGX_MODULE_V1,
    &ngx_http_ipip_module_ctx, /* module context */
    ngx_http_ipip_commands, /* module directives */
    NGX_HTTP_MODULE, /* module type */
    NULL, /* init master */
    NULL, /* init module */
    NULL, /* init process */
    NULL, /* init thread */
    NULL, /* exit thread */
    NULL, /* exit process */
    NULL, /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_http_variable_t  ngx_http_ipip_vars[] = {

    { ngx_string("ipip_country_name"), NULL,
      ngx_http_ipip_country_variable,
      0, 0, 0 },

    { ngx_string("ipip_region_name"), NULL,
      ngx_http_ipip_region_variable,
      0, 0, 0 },

    { ngx_string("ipip_city_name"), NULL,
      ngx_http_ipip_city_variable,
      0, 0, 0 },

    { ngx_string("ipip_owner_domain"), NULL,
      ngx_http_ipip_owner_domain_variable,
      0, 0, 0 },

    { ngx_string("ipip_isp_domain"), NULL,
      ngx_http_ipip_isp_domain_variable,
      0, 0, 0 },

      { ngx_string("ipip_latitude"), NULL,
      ngx_http_ipip_latitude_variable,
      0, 0, 0 },

      { ngx_string("ipip_longitude"), NULL,
      ngx_http_ipip_longitude_variable,
      0, 0, 0 },

      { ngx_string("ipip_timezone"), NULL,
      ngx_http_ipip_timezone_variable,
      0, 0, 0 },

      { ngx_string("ipip_utc_offset"), NULL,
      ngx_http_ipip_utc_offset_variable,
      0, 0, 0 },

      { ngx_string("ipip_china_admin_code"), NULL,
      ngx_http_ipip_china_admin_code_variable,
      0, 0, 0 },

      { ngx_string("ipip_idd_code"), NULL,
      ngx_http_ipip_idd_code_variable,
      0, 0, 0 },

      { ngx_string("ipip_country_code"), NULL,
      ngx_http_ipip_country_code_variable,
      0, 0, 0 },

      { ngx_string("ipip_continent_code"), NULL,
      ngx_http_ipip_continent_code_variable,
      0, 0, 0 },

      { ngx_string("ipip_idc"), NULL,
      ngx_http_ipip_idc_variable,
      0, 0, 0 },

      { ngx_string("ipip_base_station"), NULL,
      ngx_http_ipip_base_station_variable,
      0, 0, 0 },

      { ngx_string("ipip_anycast"), NULL,
      ngx_http_ipip_anycast_variable,
      0, 0, 0 },

    { ngx_null_string, NULL, NULL, 0, 0, 0 }
};

static ngx_int_t
ngx_http_ipip_addr_str(ngx_http_request_t *r, char* ipstr)
{
    ngx_addr_t           addr;
    struct sockaddr_in  *sin;

    addr.sockaddr = r->connection->sockaddr;
    addr.socklen = r->connection->socklen;

    if (addr.sockaddr->sa_family != AF_INET) {
        return INADDR_NONE;
    }

    sin = (struct sockaddr_in *) addr.sockaddr;
    inet_ntop(AF_INET, &(sin->sin_addr), ipstr, INET_ADDRSTRLEN);

    return NGX_OK;
}

static void
ngx_http_ipip_cleanup(void *data)
{
    ngx_http_ipip_conf_t  *icf = data;

    if (icf->db_ctx) {
        destroy(icf->db_ctx);
        icf->db_ctx = NULL;
    }
}

static void *
ngx_http_ipip_create_conf(ngx_conf_t *cf)
{
    ngx_pool_cleanup_t     *cln;
    ngx_http_ipip_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_ipip_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    cln = ngx_pool_cleanup_add(cf->pool, 0);
    if (cln == NULL) {
        return NULL;
    }

    cln->handler = ngx_http_ipip_cleanup;
    cln->data = conf;

    return conf;
}

static ngx_int_t
ngx_http_ipip_region_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {

    return ngx_ipip_set_variable(r, v, NGX_IPIP_REGION_NAME_COEE);
}
static ngx_int_t 
ngx_http_ipip_city_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {

    return ngx_ipip_set_variable(r, v, NGX_IPIP_CITY_NAME_CODE);
}
static ngx_int_t 
ngx_http_ipip_owner_domain_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_OWNER_DOMAIN_CODE);
}
static ngx_int_t ngx_http_ipip_isp_domain_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_ISP_DOMAIN_CODE);
}
static ngx_int_t ngx_http_ipip_latitude_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_LATITUDE_CODE);
}
static ngx_int_t ngx_http_ipip_longitude_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_LONGITUDE_CODE);
}
static ngx_int_t
ngx_http_ipip_country_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_COUNTRY_NAME_CODE);
}
static ngx_int_t
ngx_http_ipip_timezone_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_TIMEZONE_CODE);
}
static ngx_int_t ngx_http_ipip_utc_offset_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_UTC_OFFSET_CODE);
}
static ngx_int_t ngx_http_ipip_china_admin_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_CHINA_ADMIN_CODE);
}
static ngx_int_t ngx_http_ipip_idd_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_IDD_CODE_CODE);
}
static ngx_int_t ngx_http_ipip_country_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_COUNTRY_CODE_CODE);
}
static ngx_int_t ngx_http_ipip_continent_code_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_CONTINENT_CODE_CODE);
}
static ngx_int_t ngx_http_ipip_idc_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_IDC_CODE);
}
static ngx_int_t ngx_http_ipip_base_station_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_BASE_STATION_CODE);
}
static ngx_int_t ngx_http_ipip_anycast_variable(ngx_http_request_t *r,
    ngx_http_variable_value_t *v, uintptr_t data) {
    return ngx_ipip_set_variable(r, v, NGX_IPIP_ANYCAST_CODE);
}

static ngx_int_t
ngx_http_ipip_add_variables(ngx_conf_t *cf)
{
    ngx_http_variable_t  *var, *v;

    for (v = ngx_http_ipip_vars; v->name.len; v++) {
        var = ngx_http_add_variable(cf, &v->name, v->flags);
        if (var == NULL) {
            return NGX_ERROR;
        }

        var->get_handler = v->get_handler;
        var->data = v->data;
    }
    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "enter ipip add variables");

    return NGX_OK;
}

static char *ngx_http_ipip_db(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_str_t  *value;
    ngx_http_ipip_conf_t *icf = conf;
    time_t interval;

    value = cf->args->elts;
    int error_code = 0;
    icf->db_ctx = init_db((char *) value[1].data, &error_code, cf);

    icf->db_name.data = ngx_pnalloc(cf->pool, value[1].len+1);
    icf->db_name.len = value[1].len;
    ngx_memcpy(icf->db_name.data, value[1].data, icf->db_name.len);

    icf->last_check = icf->last_change = ngx_time();
    interval = ngx_parse_time(&value[2], 1);

    ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                           "check interval = %d", (ngx_int_t)interval);

    if (interval == (time_t) NGX_ERROR) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                           "invalid interval for auto_reload \"%V\"",
                           value[1]);
        return NGX_CONF_ERROR;
    }
    icf->check_interval = interval;

    if (icf->db_ctx != NULL) {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "ipip open db = %s success", (char *) value[1].data);
    } else {
        ngx_conf_log_error(NGX_LOG_NOTICE, cf, 0,
                               "ipip open db = %s failed, error code = %d",
                               (char *) value[1].data, error_code);
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
} /* ngx_http_ipip_db */

static ngx_int_t ngx_http_ipip_reload_db(ngx_http_ipip_conf_t  *icf) {

    struct DBContext *tmp_ctx;
    struct stat  attr;
    int error_code = 0;

    if (icf->check_interval > 0
            && icf->last_check + icf->check_interval <= ngx_time()) {
        icf->last_check = ngx_time();
        stat((char *) icf->db_name.data, &attr);

        if (attr.st_mtime > icf->last_change) {
            //destroy(icf->db_ctx);
            //icf->db_ctx = NULL;
            tmp_ctx = init_db((char *) icf->db_name.data, &error_code, NULL);

            if (tmp_ctx == NULL) {
                //ngx_conf_log_error(NGX_LOG_NOTICE, ncf, 0,
                //               "ipip open db = %s failed, error code = %d",
                //               (char *) value[1].data, error_code);
                return NGX_ERROR;
            }

            icf->last_change = attr.st_mtime;

            destroy(icf->db_ctx);
            icf->db_ctx = tmp_ctx;

            //ngx_conf_log_error(NGX_LOG_NOTICE, ncf, 0,
            //                   "ipip reload db %s success ", (char *) value[1].data);
        }
    } 
    return NGX_OK;
}

static char *ngx_ipip_parse_ip(ngx_conf_t *cf, ngx_command_t *cmd, void *conf)
{
    ngx_ipip_add_parse_ip_variable(cf, cmd, NULL);
    return NGX_CONF_OK;
} /* ngx_ipip_parse_ip */

static char *ngx_ipip_add_parse_ip_variable(ngx_conf_t *cf, ngx_command_t *dummy, 
    void *handler_conf) {
    ngx_str_t* value;
    ngx_str_t name, source;
    ngx_http_compile_complex_value_t ccv;
    
    ngx_http_ipip_conf_t* icf = ngx_http_conf_get_module_main_conf(cf, ngx_http_ipip_module);

    value = cf->args->elts;
    name = value[0];
    source = value[1];
    if (source.data[0] != '$') {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "invalid variable source %s", source.data);
        return NGX_CONF_ERROR;
    }

    ngx_memzero(&ccv, sizeof(ngx_http_compile_complex_value_t));
    ccv.cf = cf;
    ccv.value = &source;
    ccv.complex_value = &icf->ip_source;

    if (ngx_http_compile_complex_value(&ccv) != NGX_OK) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0,
                                "unable to compile \"%V\" for \"$%V\"", &source, &name);
        return NGX_CONF_ERROR;
    }
    return NGX_CONF_OK;
}