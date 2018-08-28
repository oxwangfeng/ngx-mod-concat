
/*
 * std@jd.com
 * www.jd.com
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct {
    ngx_int_t    enable;
    ngx_uint_t   max_files;
    ngx_flag_t   unique;
    ngx_str_t    delimiter;
    ngx_flag_t   ignore_file_error;
    ngx_hash_t   types;
    ngx_array_t  *types_keys;
} jinx_concat_srv_conf_t;


typedef struct {
    ngx_int_t           done;
    ngx_int_t           nelts;
    ngx_int_t           pendings;
    ngx_array_t         srs;
} jinx_concat_ctx_t;

static ngx_int_t jinx_http_concat_add_uri(ngx_http_request_t *r,
    ngx_array_t *uris, size_t max, u_char *p, u_char *v);

static ngx_int_t jinx_concat_sr_post_handler(ngx_http_request_t *r, void *data,
    ngx_int_t rc);
static void jinx_concat_pr_post_handler(ngx_http_request_t *r);

static ngx_int_t ngx_http_cc_subrequest(ngx_http_request_t *r, ngx_str_t *uri,
    ngx_str_t *args, ngx_http_request_t **psr, ngx_http_post_subrequest_t *ps,
	ngx_list_t *headers, ngx_uint_t flags);

static void *jinx_concat_create_srv_conf(ngx_conf_t *cf);
static char *jinx_concat_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child);
static ngx_int_t jinx_concat_init(ngx_conf_t *cf);


static ngx_str_t  jinx_http_concat_default_types[] = {
    ngx_string("application/x-javascript"),
    ngx_string("text/css"),
    ngx_null_string
};


static ngx_command_t jinx_concat_commands[] = {
    {
      ngx_string("jinx_concat"),
      NGX_HTTP_MAIN_CONF | NGX_HTTP_SRV_CONF | NGX_CONF_FLAG | NGX_CONF_TAKE1,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(jinx_concat_srv_conf_t, enable),
      NULL
    },

    {
      ngx_string("concat_max_files"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(jinx_concat_srv_conf_t, max_files),
      NULL
    },

    {
      ngx_string("concat_unique"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(jinx_concat_srv_conf_t, unique),
      NULL
    },

    {
      ngx_string("concat_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(jinx_concat_srv_conf_t, types_keys),
      &jinx_http_concat_default_types[0]
    },

    {
      ngx_string("concat_delimiter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(jinx_concat_srv_conf_t, delimiter),
      NULL
    },

    {
      ngx_string("concat_ignore_file_error"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_SRV_CONF_OFFSET,
      offsetof(jinx_concat_srv_conf_t, ignore_file_error),
      NULL
    },

    ngx_null_command
};


static ngx_http_module_t jinx_concat_module_ctx = {
    NULL,                               /* preconfiguration */
    jinx_concat_init,                   /* postconfiguration */

    NULL,                               /* create main configuration */
    NULL,                               /* init main configuration */

    jinx_concat_create_srv_conf,        /* create server configuration */
    jinx_concat_merge_srv_conf,         /* merge server configuration */

    NULL,                               /* create location configuration */
    NULL                                /* merge location configuration */
};


ngx_module_t ngx_http_jinx_concat_module = {
    NGX_MODULE_V1,
    &jinx_concat_module_ctx,                /* module context */
    jinx_concat_commands,                   /* module directives */
    NGX_HTTP_MODULE,                        /* module type */
    NULL,                                   /* init master */
    NULL,                                   /* init module */
    NULL,                                   /* init process */
    NULL,                                   /* init thread */
    NULL,                                   /* exit thread */
    NULL,                                   /* exit process */
    NULL,                                   /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_int_t
ngx_http_jinx_concat_handler(ngx_http_request_t *r)
{
    jinx_concat_srv_conf_t     *scf;
    ngx_http_request_t         *sr, **sr2;
    jinx_concat_ctx_t          *ctx;
    ngx_http_post_subrequest_t *psr;

    size_t                     last_len;
    u_char                     *p, *v, *e, *last_type;
    ngx_int_t                  rc;
    ngx_str_t                  *uri, *filename;
    ngx_uint_t                 i,j;
    ngx_array_t                uris;
	
    ngx_list_t                 *headers;
    ngx_list_part_t            *part;
    ngx_table_elt_t            *header;
    ngx_table_elt_t            *h;

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "jinx concat parse uri(%V)", &r->uri);

    if (r != r->main) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "jinx concat current request is sub request");
        return NGX_DECLINED;
    }

    if (r->uri.data[r->uri.len - 1] != '/') {
        return NGX_DECLINED;
    }

    if (!(r->method & (NGX_HTTP_GET|NGX_HTTP_HEAD))) {
        return NGX_DECLINED;
    }

    scf = ngx_http_get_module_srv_conf(r, ngx_http_jinx_concat_module);
    if (!scf->enable) {
        return NGX_DECLINED;
    }

    /* the length of args must be greater than or equal to 2 */
    if (r->args.len < 2 || r->args.data[0] != '?') {
        return NGX_DECLINED;
    }

    ctx = ngx_http_get_module_ctx(r, ngx_http_jinx_concat_module);
    if (ctx != NULL) {

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "jinx concat parent request rewrite handler，ctx done %ui",
            ctx->done);

        return NGX_DONE;
    }

    // satisfy concat prerequisite && first handling
    rc = ngx_http_discard_request_body(r);
    if (rc != NGX_OK) {
        return rc;
    }

    ctx = ngx_pcalloc(r->pool, sizeof(jinx_concat_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    ctx->pendings = 0;
    ctx->nelts = 0;
    ngx_http_set_ctx(r, ctx, ngx_http_jinx_concat_module);

    if (ngx_array_init(&ctx->srs, r->pool, 1, sizeof(ngx_http_request_t *))//保存所有的子请求；
        != NGX_OK)
    {
        return NGX_ERROR;
    }

    ngx_log_error(NGX_LOG_ALERT, r->connection->log, 0,
        "jinx concat parse parameters start.");

#if (NGX_SUPPRESS_WARN)
    ngx_memzero(&uris, sizeof(ngx_array_t));
#endif

    if (ngx_array_init(&uris, r->pool, 8, sizeof(ngx_str_t)) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    e = r->args.data + r->args.len;
    for (p = r->args.data + 1, v = p; p != e; p++) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "jinx concat check char (%c)", *p);

        if (*p == ',') {//p=,v=?
            if (p == v) {
                v = p + 1;
                continue;
            }

            rc = jinx_http_concat_add_uri(r, &uris, scf->max_files, p, v);
            if (rc != NGX_OK) {
                return rc;
            }

            v = p + 1;

        } else if (*p == '?') {

            rc = jinx_http_concat_add_uri(r, &uris, scf->max_files, p, v);//first time,p==v;add /(p-v) to uris 
            if (rc != NGX_OK) {
                return rc;
            }

            v = p;
        }
    }

    if (p - v > 0) {
        rc = jinx_http_concat_add_uri(r, &uris, scf->max_files, p, v);
        if (rc != NGX_OK) {
            return rc;
        }
    }//上面是拆分成多个子请求；

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "jinx concat parse parameters end");

    // copy headers_in
    headers = ngx_list_create(r->pool, 20, sizeof(ngx_table_elt_t));
    if (headers == NULL) {
        return NGX_ERROR;
    }
    
    part   = &r->headers_in.headers.part;//构造头部；
    header = part->elts;
    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            header = part->elts;
            i = 0;
        }

        if (header[i].hash == 0) {
            continue;
        }

        if ((header[i].key.len == 15)&& 
		    (0 == ngx_strncasecmp(header[i].lowcase_key, 
			                      (u_char*)"accept-encoding", 
								  header[i].key.len))) {
            h = ngx_list_push(headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash        = header[i].hash;
            h->key.len     = header[i].key.len;
            h->key.data    = header[i].key.data;
            h->value.len   = 0;
            h->value.data  = (u_char*)"";
            h->lowcase_key = header[i].lowcase_key;
        } else if (0 == ngx_strncasecmp(header[i].lowcase_key, 
		                                (u_char*)"if-modified-since",
                                        header[i].key.len)) {
            continue;
        } else {
            h = ngx_list_push(headers);
            if (h == NULL) {
                return NGX_ERROR;
            }

            h->hash        = header[i].hash;
            h->key.len     = header[i].key.len;
            h->key.data    = header[i].key.data;
            h->value.len   = header[i].value.len;
            h->value.data  = header[i].value.data;
            h->lowcase_key = header[i].lowcase_key;
        }
    }

    last_len  = 0;
    last_type = NULL;
    uri       = uris.elts;
    for (i = 0; i < uris.nelts; i++) {
        filename = uri + i;
        // detect file ext name
        for (j = filename->len - 1; j > 1; j--) {
            if (filename->data[j] == '.' && filename->data[j - 1] != '/') {

                r->exten.len = filename->len - j - 1;
                r->exten.data = &filename->data[j + 1];
                break;

            } else if (filename->data[j] == '/') {
                break;
            }
        }

        r->headers_out.content_type.len = 0;
        if (ngx_http_set_content_type(r) != NGX_OK) {
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
        }

        r->headers_out.content_type_lowcase = NULL;
        if (ngx_http_test_content_type(r, &scf->types) == NULL) {
            return NGX_HTTP_BAD_REQUEST;
        }
        
        // test if all the content types are the same
        if (scf->unique) { 
             ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                           "jinx concat content unique test");
            if ((i > 0)
                && (last_len != r->headers_out.content_type_len
                    || (last_type != NULL
                        && r->headers_out.content_type_lowcase != NULL
                        && ngx_memcmp(last_type,
                                      r->headers_out.content_type_lowcase,
                                      last_len) != 0)))
            {
		        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                              "jinx contact content type is not same");
                return NGX_HTTP_BAD_REQUEST;
            }

            last_len  = r->headers_out.content_type_len;
            last_type = r->headers_out.content_type_lowcase;
        }
		    
        psr = ngx_palloc(r->pool, sizeof(ngx_http_post_subrequest_t));
        if (psr == NULL) {
            return NGX_ERROR;
        }
        psr->handler = jinx_concat_sr_post_handler;//主请求，收集所有的自请求的缓冲区信息，然后发送；

        if (NGX_OK != ngx_http_cc_subrequest(r, uri+i, NULL, &sr, psr, headers,//这个应该是创建自请求，psr指向创建子请求的首地址；
                                             NGX_HTTP_SUBREQUEST_IN_MEMORY)) {
            return NGX_ERROR;
        }

        sr2 = ngx_array_push(&ctx->srs);
        if (sr2 == NULL) {
            return NGX_ERROR;
        }
        *sr2 = sr;//

        ctx->pendings ++;
        ctx->nelts ++;

        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "jinx concat create sub request (%V)", uri+i);
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "jinx concat main request have created all subs");

    return NGX_DONE;
}

//这个应该是创建自请求，psr指向创建子请求的首地址；
static ngx_int_t
ngx_http_cc_subrequest(ngx_http_request_t *r, ngx_str_t *uri, ngx_str_t *args,
    ngx_http_request_t **psr, ngx_http_post_subrequest_t *ps, ngx_list_t *headers, 
	ngx_uint_t flags)
{
    ngx_time_t                    *tp;
    ngx_connection_t              *c;
    ngx_http_request_t            *sr;
    ngx_http_core_srv_conf_t      *cscf;
    
    r->main->subrequests--;

    if (r->main->subrequests == 0) {
#if defined(NGX_DTRACE) && NGX_DTRACE
        ngx_http_probe_subrequest_cycle(r, uri, args);
#endif

        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
                      "subrequests cycle while processing \"%V\"", uri);
        r->main->subrequests = 1;
        return NGX_ERROR;
    }

    sr = ngx_pcalloc(r->pool, sizeof(ngx_http_request_t));//一个子请求？
    if (sr == NULL) {
        return NGX_ERROR;
    }

    sr->signature = NGX_HTTP_MODULE;

    c = r->connection;
    sr->connection = c;

    sr->ctx = ngx_pcalloc(r->pool, sizeof(void *) * ngx_http_max_module);
    if (sr->ctx == NULL) {
        return NGX_ERROR;
    }

    if (ngx_list_init(&sr->headers_out.headers, r->pool, 20,
                      sizeof(ngx_table_elt_t)) != NGX_OK)
    {
        return NGX_ERROR;
    }

    cscf = ngx_http_get_module_srv_conf(r, ngx_http_core_module);
    sr->main_conf = cscf->ctx->main_conf;
    sr->srv_conf  = cscf->ctx->srv_conf;
    sr->loc_conf  = cscf->ctx->loc_conf;

    sr->pool = r->pool;

    sr->headers_in.headers           = *headers;
    sr->headers_in.content_length_n  = -1;
    sr->headers_in.keep_alive_n      = -1;
    //sr->headers_in.if_modified_since = r->headers_in.if_modified_since;
    
    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    ngx_http_clear_content_length(sr);
    ngx_http_clear_accept_ranges(sr);
    //ngx_http_clear_last_modified(sr);

    sr->request_body = r->request_body;

#if (NGX_HTTP_SPDY)
    sr->spdy_stream = r->spdy_stream;
#endif

#ifdef HAVE_ALLOW_REQUEST_BODY_UPDATING_PATCH
    sr->content_length_n = -1;
#endif

    sr->method = NGX_HTTP_GET;
    sr->http_version = r->http_version;
    sr->request_line = r->request_line;
    sr->uri = *uri;

    if (args) {
        sr->args = *args;
    }

    ngx_log_debug2(NGX_LOG_DEBUG_HTTP, c->log, 0,
                   "http subrequest \"%V?%V\"", uri, &sr->args);

    sr->subrequest_in_memory = (flags & NGX_HTTP_SUBREQUEST_IN_MEMORY) != 0;
    sr->waited               = (flags & NGX_HTTP_SUBREQUEST_WAITED) != 0;

    sr->unparsed_uri  = r->unparsed_uri;
    sr->method_name   = ngx_http_core_get_method;
    sr->http_protocol = r->http_protocol;

    ngx_http_set_exten(sr);

    sr->main                = r->main;
    sr->parent              = r;
    sr->post_subrequest     = ps;
    sr->read_event_handler  = ngx_http_request_empty_handler;
    sr->write_event_handler = ngx_http_handler;

    sr->variables = r->variables;

    sr->log_handler = r->log_handler;

    sr->internal = 1;

    sr->discard_body = r->discard_body;
    sr->expect_tested = 1;
    sr->main_filter_need_in_memory = r->main_filter_need_in_memory;

    sr->uri_changes = NGX_HTTP_MAX_URI_CHANGES + 1;

    tp = ngx_timeofday();
    sr->start_sec = tp->sec;
    sr->start_msec = tp->msec;

    r->main->count++;

    *psr = sr;

#if defined(NGX_DTRACE) && NGX_DTRACE
    ngx_http_probe_subrequest_start(sr);
#endif

    return ngx_http_post_request(sr, NULL);
}


static ngx_int_t
jinx_http_concat_add_uri(ngx_http_request_t *r, ngx_array_t *uris, size_t max,
    u_char *p, u_char *v)
{
    ngx_str_t  *uri, args;
    ngx_uint_t  flags;

    if (p == v) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "client sent zero concat filename");
        return NGX_HTTP_BAD_REQUEST;
    }

    if (uris->nelts >= max) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0,
            "client sent too many concat filenames");
        return NGX_HTTP_BAD_REQUEST;
    }

    uri = ngx_array_push(uris);
    if (uri == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    uri->len = 1 + p - v;//p>v
    uri->data = ngx_pnalloc(r->pool, uri->len);
    if (uri->data == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    *uri->data = '/';

    ngx_memcpy(uri->data + 1, v, p - v);

    args.len = 0;
    args.data = NULL;
    flags = NGX_HTTP_LOG_UNSAFE;

    if (ngx_http_parse_unsafe_uri(r, uri, &args, &flags) != NGX_OK) {
        return NGX_HTTP_BAD_REQUEST;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "jinx concat add uri(%V)", uri);

    return NGX_OK;
}

//发送header和body；
static ngx_int_t
jinx_concat_sr_post_handler(ngx_http_request_t *r, void *data, ngx_int_t rc)
{
    ngx_http_request_t      *pr;
    jinx_concat_ctx_t       *ctx;

    pr = r->parent;
    ctx = ngx_http_get_module_ctx(pr,ngx_http_jinx_concat_module);

    pr->count--;

    ctx->pendings--;//每个子请求执行结束，--

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "jinx concat sub request finished (%V)", &r->uri);

    pr->write_event_handler = jinx_concat_pr_post_handler;

    if (ctx->pendings == 0) {
        ctx->done = 1;
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "jinx concat parent request resume to run");
    }

    // return r->headers_out.status;
    return NGX_OK;
}

//向request r发送header和body；
static void
jinx_concat_pr_post_handler(ngx_http_request_t *r)//pr prente
{
    jinx_concat_ctx_t       *ctx;
    ngx_chain_t             *out, *pc, *out2;
    ngx_uint_t              j, content_len;
    ngx_http_request_t      *sr, **sr2;
    time_t                  last_modified_time, sub_last_modified;
    ngx_int_t               rc, last_modified_err;
    

    ctx = ngx_http_get_module_ctx(r, ngx_http_jinx_concat_module);

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "jinx concat pr post handler ctx check done flag");

    if (ctx->done != 1) {
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                      "jinx concat pr post handler ctx haven't done");
        return;
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                  "jinx concat pr post handler init response body");

    out = (ngx_chain_t *)ngx_pnalloc(r->pool, sizeof(ngx_chain_t));
    if (out == NULL) {
        return;
    }
    out->buf = NULL;
    out->next = NULL;
    pc = out;

    sr2 = ctx->srs.elts;
    content_len = 0;
    if (ctx->srs.nelts > 0) {
        last_modified_time = sr2[0]->headers_out.last_modified_time;
    } else {
        last_modified_time = ngx_time();
    }

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "jinx concat last modified time init: (%d), current time:(%d)",
        last_modified_time, ngx_time());
   
    last_modified_err = 0;
    for (j = 0; j < ctx->srs.nelts; j++) {//针对每个子请求，处理，
        sr = sr2[j];//sr表示每个子请求；
		if (last_modified_err == 0) {//求出last modify time;
			sub_last_modified = ngx_http_parse_time(sr->headers_out.last_modified->value.data, 
                                                    sr->headers_out.last_modified->value.len);
	        if (NGX_ERROR != sub_last_modified) {
			    sr->headers_out.last_modified_time = sub_last_modified;
			    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                              "jinx concat last modified time sub req: (%d), %s",
                              sr->headers_out.last_modified,
						      sr->headers_out.last_modified->value.data);

                if (last_modified_time <  sr->headers_out.last_modified_time) {
                    last_modified_time = sr->headers_out.last_modified_time;

                        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                                      "jinx concat last modified time update: (%d)",
                                      last_modified_time);
                }
		    } else {
			    last_modified_err = 1;
			    last_modified_time = ngx_time();
		    } 
		}	

        content_len = content_len + sr->headers_out.content_length_n;//求出每个content length；
        ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
            "jinx concat subrequest %d response body len %d response status %d",
            j, sr->headers_out.content_length_n, sr->headers_out.status);

        if (pc->buf == NULL) {
            pc->buf = &sr->upstream->buffer;//每个子请求的缓冲区；
        } else {
            out2 = (ngx_chain_t *)ngx_pnalloc(r->pool, sizeof(ngx_chain_t));//缓冲区；
            if (out2 == NULL) {
                return;
            }
            pc->next = out2;
            pc = out2;
            pc->buf = &sr->upstream->buffer;
            pc->next = NULL;
        }
        if (j == ctx->srs.nelts - 1) {
            pc->buf->last_buf = 1;
        }
    }
    
     ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
                   "jinx concat last modified time: (%d)",
                   last_modified_time);
    r->headers_out.status             = NGX_HTTP_OK;
    r->headers_out.date_time          = last_modified_time;
    r->headers_out.content_length_n   = content_len;    
    r->headers_out.last_modified_time = last_modified_time;//ngx_time();

    if (content_len == 0) {
        r->header_only = 1;
    }
	
    rc = ngx_http_send_header(r);
    if (rc == NGX_ERROR || rc > NGX_OK || r->header_only) {
        return;
    }

    rc = ngx_http_output_filter(r, out);//out指向各个子请求组成的缓冲区的首地址；

    ngx_log_error(NGX_LOG_DEBUG, r->connection->log, 0,
        "jinx concat pr handler output filter ret (%d) r->keepalive (%ui)",
        rc, r->keepalive);

    ngx_http_finalize_request(r, rc);
}


static void *
jinx_concat_create_srv_conf(ngx_conf_t *cf)
{
    jinx_concat_srv_conf_t  *conf;

    conf = ngx_pcalloc(cf->pool, sizeof(jinx_concat_srv_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable            = NGX_CONF_UNSET;
    conf->ignore_file_error = NGX_CONF_UNSET;
    conf->max_files         = NGX_CONF_UNSET_UINT;
    conf->unique            = NGX_CONF_UNSET;

    return conf;
}


static char *
jinx_concat_merge_srv_conf(ngx_conf_t *cf, void *parent, void *child)
{
    jinx_concat_srv_conf_t *prev = parent;
    jinx_concat_srv_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_str_value(conf->delimiter, prev->delimiter, "");
    ngx_conf_merge_value(conf->ignore_file_error, prev->ignore_file_error, 0);
    ngx_conf_merge_uint_value(conf->max_files, prev->max_files, 10);
    ngx_conf_merge_value(conf->unique, prev->unique, 1);

    if (ngx_http_merge_types(cf, &conf->types_keys, &conf->types,
                             &prev->types_keys, &prev->types,
                             jinx_http_concat_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
jinx_concat_init(ngx_conf_t *cf)
{
    ngx_http_handler_pt        *h;
    ngx_http_core_main_conf_t  *cmcf;

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    h = ngx_array_push(&cmcf->phases[NGX_HTTP_REWRITE_PHASE].handlers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    *h = ngx_http_jinx_concat_handler;

    return NGX_OK;
}
