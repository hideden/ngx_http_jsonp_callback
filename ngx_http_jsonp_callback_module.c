
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t     arg_name;
    ngx_hash_t    types;
    ngx_array_t   *types_keys;
} ngx_http_jsonp_callback_loc_conf_t;


typedef struct {
    ngx_uint_t    before_body_sent;
    ngx_str_t     callback;
} ngx_http_jsonp_callback_ctx_t;


static void *ngx_http_jsonp_callback_create_conf(ngx_conf_t *cf);
static char *ngx_http_jsonp_callback_merge_conf(ngx_conf_t *cf,
    void *parent, void *child);
static ngx_int_t ngx_http_jsonp_callback_filter_init(ngx_conf_t *cf);


static ngx_command_t  ngx_http_jsonp_callback_filter_commands[] = {

    { ngx_string("jsonp_callback"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jsonp_callback_loc_conf_t, arg_name),
      NULL },

    { ngx_string("jsonp_callback_types"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_1MORE,
      ngx_http_types_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jsonp_callback_loc_conf_t, types_keys),
      &ngx_http_html_default_types[0] },

      ngx_null_command
};


static ngx_http_module_t  ngx_http_jsonp_callback_filter_module_ctx = {
    NULL,                                  /* preconfiguration */
    ngx_http_jsonp_callback_filter_init,   /* postconfiguration */

    NULL,                                  /* create main configuration */
    NULL,                                  /* init main configuration */

    NULL,                                  /* create server configuration */
    NULL,                                  /* merge server configuration */

    ngx_http_jsonp_callback_create_conf,   /* create location configuration */
    ngx_http_jsonp_callback_merge_conf     /* merge location configuration */
};


ngx_module_t  ngx_http_jsonp_callback_filter_module = {
    NGX_MODULE_V1,
    &ngx_http_jsonp_callback_filter_module_ctx, /* module context */
    ngx_http_jsonp_callback_filter_commands,    /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};


static ngx_http_output_header_filter_pt  ngx_http_next_header_filter;
static ngx_http_output_body_filter_pt    ngx_http_next_body_filter;

static ngx_int_t
ngx_http_jsonp_callback_header_filter(ngx_http_request_t *r)
{
    ngx_http_jsonp_callback_ctx_t        *ctx;
    ngx_http_jsonp_callback_loc_conf_t   *jccf;

    jccf = ngx_http_get_module_loc_conf(r, ngx_http_jsonp_callback_filter_module);

    if (jccf->arg_name.len == 0
        || r->headers_out.status != NGX_HTTP_OK
        || r->header_only
        || r->headers_out.content_length_n == 0
        || (r->headers_out.content_encoding
            && r->headers_out.content_encoding->value.len)
        || ngx_http_test_content_type(r, &jccf->types) == NULL)
    {
        return ngx_http_next_header_filter(r);
    }

    ngx_str_t args = r->args;
    ngx_str_t look = jccf->arg_name;
    ngx_uint_t i=0,j=0,st=0,ed=0,ln=0,ng=0;

    for (i = 0; i <= args.len; i++) {
        if (i == args.len || args.data[i] == '&') {
            if (j > 1) { st = j; ed = i; ln = ed-st; }
            j = 0;
        } else if (j == 0 && (i<args.len-look.len) ) {
            if ((ngx_strncmp(args.data+i, look.data, look.len) == 0)
                    && (args.data[i+look.len] == '=') ) {
                j=i+look.len+1;
                i=j-1;
            } else j=1;
        } else if (j > 1 && !((args.data[i] >= 'a' && args.data[i] <= 'z')
                            ||(args.data[i] >= 'A' && args.data[i] <= 'Z')
                            ||(args.data[i] >= '0' && args.data[i] <= '9')
                            || args.data[i] == '_')) {
            ng = 1;
        }
    }

    if (ln==0 || ng==1 || ln>255) {
        return ngx_http_next_header_filter(r);
    }

    ctx = ngx_pcalloc(r->pool, sizeof(ngx_http_jsonp_callback_ctx_t));
    if (ctx == NULL) {
        return NGX_ERROR;
    }
    u_char  *val;
    val = ngx_palloc(r->pool, ln+2);
    ngx_memcpy(val, args.data+st, ln);
    val[ln]   = '(';
    val[ln+1] = '\0';

    ctx->callback.len  = ln+1;
    ctx->callback.data = val;

    ngx_http_set_ctx(r, ctx, ngx_http_jsonp_callback_filter_module);
    
    ngx_http_clear_content_length(r);
    ngx_http_clear_last_modified(r);
    ngx_http_clear_accept_ranges(r);
    r->main_filter_need_in_memory = 1;

    return ngx_http_next_header_filter(r);
}


static ngx_int_t
ngx_http_jsonp_callback_body_filter(ngx_http_request_t *r, ngx_chain_t *in)
{
    ngx_chain_t                          *cl;
    ngx_chain_t                          *nc;
    ngx_buf_t                            *b;
    ngx_http_jsonp_callback_ctx_t        *ctx;

    ctx = ngx_http_get_module_ctx(r, ngx_http_jsonp_callback_filter_module);

    if (ctx == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (ctx->callback.len == 0) {
        return ngx_http_next_body_filter(r, in);
    }

    if (in == NULL) {
        return ngx_http_next_body_filter(r, in);
    }

    if (!ctx->before_body_sent) {
        ctx->before_body_sent = 1;
        b = ngx_calloc_buf(r->pool);
        if (b == NULL) {
            return NGX_ERROR;
        }
        nc = ngx_alloc_chain_link(r->pool);
        if (nc == NULL) {
            return NGX_ERROR;
        }
        nc->buf = b;
        nc->next = in;

        b->memory = 1;
        b->pos  = ctx->callback.data;
        b->last = b->pos + ctx->callback.len;
        b->last_buf = 0;
        in = nc;
    }

    for (cl=in; cl; cl=cl->next) {
        if (cl->buf->last_buf) {
            b = ngx_calloc_buf(r->pool);
            if (b == NULL) {
                return NGX_ERROR;
            }
            nc = ngx_alloc_chain_link(r->pool);
            if (nc == NULL) {
                return NGX_ERROR;
            }
            nc->buf = b;
            nc->next = NULL;

            b->memory = 1;
            b->pos  = (u_char *) ");";
            b->last = b->pos + sizeof(");") - 1;
            b->last_buf = 1;

            cl->buf->last_buf = 0;
            cl->buf->sync = 1;
            cl->next = nc;
            break;
        }
    }

    return ngx_http_next_body_filter(r, in);
}


static void *
ngx_http_jsonp_callback_create_conf(ngx_conf_t *cf)
{
    ngx_http_jsonp_callback_loc_conf_t  *jccf;

    jccf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jsonp_callback_loc_conf_t));
    if (jccf == NULL) {
        return NGX_CONF_ERROR;
    }
    return jccf;
}


static char *
ngx_http_jsonp_callback_merge_conf(ngx_conf_t *cf, void *parent, void *child)
{
    ngx_http_jsonp_callback_loc_conf_t *prev = parent;
    ngx_http_jsonp_callback_loc_conf_t *conf = child;

    ngx_conf_merge_str_value(conf->arg_name, prev->arg_name, "");

    if (ngx_http_merge_types(cf, conf->types_keys, &conf->types,
                             prev->types_keys, &prev->types,
                             ngx_http_html_default_types)
        != NGX_OK)
    {
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}


static ngx_int_t
ngx_http_jsonp_callback_filter_init(ngx_conf_t *cf)
{
    ngx_http_next_header_filter = ngx_http_top_header_filter;
    ngx_http_top_header_filter = ngx_http_jsonp_callback_header_filter;

    ngx_http_next_body_filter = ngx_http_top_body_filter;
    ngx_http_top_body_filter = ngx_http_jsonp_callback_body_filter;

    return NGX_OK;
}
