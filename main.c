
/*
 * RupeeSense — C Edition
 * C backend using GNU libmicrohttpd, libcurl and cJSON.
 * Supabase Auth + PostgREST are used for persistent application data.
 */
#define _GNU_SOURCE
#include <microhttpd.h>
#include <curl/curl.h>
#include <cjson/cJSON.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>
#include <ctype.h>

#define APP_NAME "RupeeSense"
#define MAX_BODY 65536
#define MAX_SESSIONS 256

typedef struct { char *data; size_t size; } Buffer;
typedef struct {
    char sid[80];
    char token[4096];
    cJSON *user;
    time_t touched;
} Session;

static Session sessions[MAX_SESSIONS];
static const char *SUPABASE_URL, *SUPABASE_KEY;
static char *PORT;
static const char *CSS =
"<link rel=\"stylesheet\" href=\"/style.css\"><meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">";

static size_t write_cb(void *contents, size_t size, size_t nmemb, void *userp) {
    size_t n=size*nmemb; Buffer *b=(Buffer*)userp;
    char *p=realloc(b->data,b->size+n+1); if(!p) return 0;
    b->data=p; memcpy(b->data+b->size,contents,n); b->size+=n; b->data[b->size]=0;
    return n;
}
static char *dupstr(const char *s) { return strdup(s?s:""); }
static const char *envv(const char *k,const char *d) { const char *v=getenv(k); return v&&*v?v:d; }

static char *url_encode(const char *s) {
    CURL *c=curl_easy_init(); if(!c) return dupstr("");
    char *e=curl_easy_escape(c,s?s:"",0); char *r=dupstr(e?e:"");
    if(e) curl_free(e); curl_easy_cleanup(c); return r;
}
static char *html_escape(const char *s) {
    if(!s) return dupstr("");
    size_t cap=strlen(s)*6+1; char *o=calloc(1,cap);
    for(size_t i=0,j=0;s[i];i++) {
        const char *x=NULL;
        switch(s[i]) { case '&':x="&amp;";break; case '<':x="&lt;";break;
        case '>':x="&gt;";break; case '"':x="&quot;";break; case '\'':x="&#39;";break; }
        if(x){strcat(o,x);j+=strlen(x);} else {o[j++]=s[i];}
    } return o;
}
static char *json_string(cJSON *o,const char *key,const char *fallback) {
    cJSON *v=cJSON_GetObjectItemCaseSensitive(o,key);
    return dupstr(cJSON_IsString(v)?v->valuestring:fallback);
}
static char *money(double v) { char b[80]; snprintf(b,sizeof b,"₹%.2f",v); return dupstr(b); }

static char *supabase(const char *path,const char *method,const char *token,const char *body,
                      const char *prefer,long *status) {
    CURL *c=curl_easy_init(); if(!c) return dupstr("{}");
    Buffer b={calloc(1,1),0}; struct curl_slist *h=NULL;
    char auth[5000]; snprintf(auth,sizeof auth,"Authorization: Bearer %s",token&&*token?token:SUPABASE_KEY);
    char key[2048]; snprintf(key,sizeof key,"apikey: %s",SUPABASE_KEY);
    h=curl_slist_append(h,key); h=curl_slist_append(h,auth);
    h=curl_slist_append(h,"Content-Type: application/json");
    if(prefer) { char p[256]; snprintf(p,sizeof p,"Prefer: %s",prefer); h=curl_slist_append(h,p); }
    char url[4096]; snprintf(url,sizeof url,"%s%s",SUPABASE_URL,path);
    curl_easy_setopt(c,CURLOPT_URL,url); curl_easy_setopt(c,CURLOPT_HTTPHEADER,h);
    curl_easy_setopt(c,CURLOPT_WRITEFUNCTION,write_cb); curl_easy_setopt(c,CURLOPT_WRITEDATA,&b);
    curl_easy_setopt(c,CURLOPT_TIMEOUT,25L); curl_easy_setopt(c,CURLOPT_FOLLOWLOCATION,0L);
    if(!strcmp(method,"POST")) { curl_easy_setopt(c,CURLOPT_POST,1L); if(body) curl_easy_setopt(c,CURLOPT_POSTFIELDS,body); }
    else if(strcmp(method,"GET")) { curl_easy_setopt(c,CURLOPT_CUSTOMREQUEST,method); if(body) curl_easy_setopt(c,CURLOPT_POSTFIELDS,body); }
    curl_easy_perform(c); curl_easy_getinfo(c,CURLINFO_RESPONSE_CODE,status);
    curl_slist_free_all(h); curl_easy_cleanup(c); return b.data?b.data:dupstr("{}");
}
static cJSON *parse_json(char *s) { cJSON *j=cJSON_Parse(s?s:""); free(s); return j; }
static char *json_print(cJSON *j) { char *s=cJSON_PrintUnformatted(j); return s?s:dupstr("{}"); }

static Session *session_for(struct MHD_Connection *con) {
    const char *cookie=MHD_lookup_connection_value(con,MHD_COOKIE_KIND,"rsid");
    if(!cookie) return NULL;
    for(int i=0;i<MAX_SESSIONS;i++) if(sessions[i].sid[0]&&!strcmp(sessions[i].sid,cookie)) {
        sessions[i].touched=time(NULL); return &sessions[i];
    }
    return NULL;
}
static Session *new_session(void) {
    int slot=-1; time_t oldest=0;
    for(int i=0;i<MAX_SESSIONS;i++) {
        if(!sessions[i].sid[0]) {slot=i;break;}
        if(!sessions[i].user || sessions[i].touched<oldest || !oldest) {oldest=sessions[i].touched;slot=i;}
    }
    if(slot<0) slot=0;
    if(sessions[slot].user) cJSON_Delete(sessions[slot].user);
    memset(&sessions[slot],0,sizeof(Session));
    snprintf(sessions[slot].sid,sizeof sessions[slot].sid,"%lx%lx",(unsigned long)time(NULL),(unsigned long)random());
    sessions[slot].touched=time(NULL); return &sessions[slot];
}
static void clear_session(Session *s) { if(s){ if(s->user)cJSON_Delete(s->user); memset(s,0,sizeof *s); } }

static char *page_start(const char *title) {
    char *p=calloc(1,4096);
    snprintf(p,4096,"<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\"><title>%s · RupeeSense</title>%s</head><body>",title,CSS);
    return p;
}
static char *auth_page(const char *message) {
    char *p=page_start("Welcome"); char *m=html_escape(message);
    const char *body="<section class=\"auth-shell\"><div class=\"auth-art\"><div class=\"auth-stamp\">RUPEESENSE · EST. 2026</div><div class=\"auth-quote\">Your money,<br><em>in good order.</em></div><div class=\"auth-caption\">A QUIETER WAY TO TRACK, SAVE & SHARE.</div><div class=\"auth-orbit\"><span>₹</span><i>MINDFUL MONEY</i></div></div><div class=\"auth-panel\"><a class=\"brand\" href=\"/\">RupeeSense<small>PERSONAL FINANCE, SOFTLY</small></a><div class=\"eyebrow\">WELCOME BACK</div><h1>Make room<br>for <em>what matters.</em></h1><p>Track your spending, save for what matters, and split shared expenses.</p>";
    char *out=calloc(1,12000);
    snprintf(out,12000,"%s%s%s%s<form class=\"auth-form\" action=\"/auth\" method=\"post\"><input type=\"hidden\" name=\"mode\" value=\"login\"><label>Email address</label><input type=\"email\" name=\"email\" required placeholder=\"you@example.com\"><label>Password</label><input type=\"password\" name=\"password\" required><button class=\"btn btn-dark full\">Sign in</button></form><div class=\"auth-divider\">OR CREATE YOUR ACCOUNT</div><form class=\"auth-form\" action=\"/auth\" method=\"post\"><input type=\"hidden\" name=\"mode\" value=\"signup\"><label>Your name</label><input name=\"full_name\" required placeholder=\"Full name\"><label>Email address</label><input type=\"email\" name=\"email\" required><label>Password</label><input type=\"password\" name=\"password\" minlength=\"6\" required><button class=\"btn btn-outline full\">Create account</button></form><div class=\"auth-foot\">◈ &nbsp; Your finances, your privacy, your pace.</div></div></section></body></html>",p,body,*m?"<div class=\"msg error\">":"",m);
    free(p);free(m); return out;
}
static char *get_today(void) { time_t t=time(NULL); struct tm *tm=localtime(&t); char *s=calloc(1,16); strftime(s,16,"%Y-%m-%d",tm); return s; }

typedef struct { char *body; size_t len; } Form;
static char *form_get(const char *body,const char *key) {
    char *copy=dupstr(body),*save=NULL,*part=strtok_r(copy,"&",&save),*result=dupstr("");
    while(part){char *eq=strchr(part,'=');if(eq){*eq++=0;if(!strcmp(part,key)){CURL*c=curl_easy_init();int n=0;char*d=curl_easy_unescape(c,eq,0,&n);free(result);result=d?strndup(d,n):dupstr("");if(d)curl_free(d);curl_easy_cleanup(c);break;}}part=strtok_r(NULL,"&",&save);}
    free(copy);return result;
}
static enum MHD_Result respond(struct MHD_Connection *c,const char *html,unsigned code,const char *cookie) {
    struct MHD_Response *r=MHD_create_response_from_buffer(strlen(html),(void*)html,MHD_RESPMEM_MUST_COPY);
    MHD_add_response_header(r,"Content-Type","text/html; charset=utf-8");
    MHD_add_response_header(r,"X-Content-Type-Options","nosniff");
    if(cookie) MHD_add_response_header(r,"Set-Cookie",cookie);
    enum MHD_Result ret=MHD_queue_response(c,code,r);MHD_destroy_response(r);return ret;
}
static enum MHD_Result redirect_to(struct MHD_Connection *c,const char *where,const char *cookie) {
    struct MHD_Response *r=MHD_create_response_from_buffer(0,"",MHD_RESPMEM_PERSISTENT);
    MHD_add_response_header(r,"Location",where);if(cookie)MHD_add_response_header(r,"Set-Cookie",cookie);
    enum MHD_Result ret=MHD_queue_response(c,303,r);MHD_destroy_response(r);return ret;
}
static char *make_dashboard(Session *s,const char *notice) {
    char *html=calloc(1,50000),*name=json_string(s->user,"email","friend"),*today=get_today();
    cJSON *meta=cJSON_GetObjectItem(s->user,"user_metadata"); char *full=json_string(meta,"full_name",name);
    char *uid=json_string(s->user,"id",""); char path[2048];long st=0;
    snprintf(path,sizeof path,"/rest/v1/personal_transactions?user_id=eq.%s&order=txn_date.desc&limit=100",uid);
    cJSON *tx=parse_json(supabase(path,"GET",s->token,NULL,NULL,&st));
    snprintf(path,sizeof path,"/rest/v1/savings_goals?user_id=eq.%s&order=created_at.desc",uid);
    cJSON *goals=parse_json(supabase(path,"GET",s->token,NULL,NULL,&st));
    snprintf(path,sizeof path,"/rest/v1/room_members?user_id=eq.%s&select=room_id,role",uid);
    cJSON *members=parse_json(supabase(path,"GET",s->token,NULL,NULL,&st));
    double income=0,expenses=0; char txhtml[16000]="",goalhtml[8000]="",roomhtml[6000]="";
    if(cJSON_IsArray(tx)) { cJSON *x=NULL; cJSON_ArrayForEach(x,tx) {
        char *type=json_string(x,"type","expense"),*title=json_string(x,"title","Transaction"),*cat=json_string(x,"category","Other"),*date=json_string(x,"txn_date","");
        cJSON *a=cJSON_GetObjectItem(x,"amount");double amount=cJSON_IsNumber(a)?a->valuedouble:0;
        if(!strcmp(type,"income"))income+=amount;else expenses+=amount;
        char *et=html_escape(title),*ec=html_escape(cat),*amt=money(amount);
        char line[1200];snprintf(line,sizeof line,"<div class=\"transaction-line\"><div class=\"transaction-icon\">◈</div><div class=\"transaction-details\"><b>%s</b><small>%s · %s</small></div><strong class=\"%s\">%s%s</strong></div>",et,ec,date,!strcmp(type,"income")?"positive":"negative",!strcmp(type,"income")?"+":"−",amt);
        strncat(txhtml,line,sizeof(txhtml)-strlen(txhtml)-1);free(type);free(title);free(cat);free(date);free(et);free(ec);free(amt);
    }}
    if(!*txhtml)strcpy(txhtml,"<p class=\"empty-inline\">Your transactions will appear here once you add them.</p>");
    if(cJSON_IsArray(goals)){cJSON*x=NULL;cJSON_ArrayForEach(x,goals){
        char *n=json_string(x,"name","Savings goal");cJSON*a=cJSON_GetObjectItem(x,"saved_amount"),*b=cJSON_GetObjectItem(x,"target_amount");
        double saved=cJSON_IsNumber(a)?a->valuedouble:0,target=cJSON_IsNumber(b)?b->valuedouble:0;int pct=target>0?(int)(saved*100/target):0;if(pct>100)pct=100;
        char *en=html_escape(n),*ms=money(saved),*mt=money(target);char line[1000];
        snprintf(line,sizeof line,"<div class=\"goal-line\"><div><b>%s</b><small>%s saved of %s</small><div class=\"budget-progress\"><div class=\"progress\"><span style=\"width:%d%%\"></span></div></div></div><strong>%d%%</strong></div>",en,ms,mt,pct,pct);
        strncat(goalhtml,line,sizeof(goalhtml)-strlen(goalhtml)-1);free(n);free(en);free(ms);free(mt);
    }}
    if(!*goalhtml)strcpy(goalhtml,"<p class=\"empty-inline\">Create a goal to begin saving with intention.</p>");
    if(cJSON_IsArray(members)){cJSON*x=NULL;cJSON_ArrayForEach(x,members){
        char *rid=json_string(x,"room_id","");char rp[512];snprintf(rp,sizeof rp,"/rest/v1/rooms?id=eq.%s",rid);
        cJSON *rr=parse_json(supabase(rp,"GET",s->token,NULL,NULL,&st));
        if(cJSON_IsArray(rr)&&cJSON_GetArraySize(rr)){cJSON*r=cJSON_GetArrayItem(rr,0);char*n=json_string(r,"name","Shared room");char*en=html_escape(n);char line[500];snprintf(line,sizeof line,"<a class=\"room-link\" href=\"/room/%s\"><span><b>%s</b></span><small>Open room →</small></a>",rid,en);strncat(roomhtml,line,sizeof(roomhtml)-strlen(roomhtml)-1);free(n);free(en);}if(rr)cJSON_Delete(rr);free(rid);
    }}
    if(!*roomhtml)strcpy(roomhtml,"<p class=\"empty-inline\">Rooms you create or join will appear here.</p>");
    char *ei=money(income),*ee=money(expenses),*eb=money(income-expenses),*en=html_escape(full),*em=html_escape(notice?notice:"");
    snprintf(html,50000,"%s<div class=\"app-shell\"><aside class=\"sidebar\"><a class=\"brand\" href=\"/\"><span class=\"brand-mark\">₹</span><span>RUPEESENSE<small>PERSONAL FINANCE</small></span></a><div class=\"side-label\">YOUR FINANCES</div><nav><a class=\"nav-item active\" href=\"/\">◈ &nbsp; Overview</a><a class=\"nav-item\" href=\"#transactions\">↗ &nbsp; Transactions</a><a class=\"nav-item\" href=\"#goals\">◎ &nbsp; Savings goals</a><a class=\"nav-item\" href=\"#rooms\">♧ &nbsp; Shared rooms</a></nav><div class=\"sidebar-bottom\"><div class=\"side-note\"><span class=\"eyebrow\">A GENTLE REMINDER</span><p>Small choices make a steadier tomorrow.</p></div><form action=\"/logout\" method=\"post\"><button class=\"nav-item\">↪ &nbsp; Sign out</button></form></div></aside><div class=\"main-area\"><header class=\"topbar\"><div><div class=\"eyebrow\">PERSONAL FINANCE, SOFTLY</div><div class=\"page-title\">Your overview</div></div><div class=\"user-chip\"><span class=\"avatar\">%c</span><span>%s</span></div></header><main class=\"content\"><div class=\"messages\">%s</div><div class=\"welcome-row\"><div><div class=\"eyebrow\">YOUR FINANCIAL OVERVIEW</div><h1>Hello, %s.</h1><p class=\"muted\">Small choices. A steadier tomorrow.</p></div></div><section class=\"stat-grid three\"><div class=\"stat-card\"><div class=\"stat-top\">INCOME <span>↗</span></div><div class=\"stat-value positive\">%s</div><div class=\"stat-note\">Money received</div></div><div class=\"stat-card\"><div class=\"stat-top\">EXPENSES <span>↘</span></div><div class=\"stat-value negative\">%s</div><div class=\"stat-note\">Money spent</div></div><div class=\"stat-card\"><div class=\"stat-top\">NET BALANCE <span>◈</span></div><div class=\"stat-value\">%s</div><div class=\"stat-note\">Income minus expenses</div></div></section><div class=\"two-col\"><section class=\"panel\"><div class=\"panel-head\"><h2>Add transaction</h2><span class=\"pill\">PERSONAL</span></div><form class=\"modal-form\" action=\"/transaction\" method=\"post\"><div class=\"form-grid\"><label>Type<select name=\"type\"><option value=\"expense\">Expense</option><option value=\"income\">Income</option></select></label><label>Amount (₹)<input type=\"number\" name=\"amount\" step=\"0.01\" min=\"0.01\" required></label></div><label>Title<input name=\"title\" required placeholder=\"e.g. Groceries\"></label><div class=\"form-grid\"><label>Category<input name=\"category\" value=\"Other\"></label><label>Date<input type=\"date\" name=\"txn_date\" value=\"%s\"></label></div><div class=\"form-grid\"><label>Payment method<input name=\"payment_method\" value=\"UPI\"></label><label>Notes<input name=\"description\"></label></div><button class=\"btn btn-dark\">Add transaction</button></form></section><section class=\"panel\" id=\"goals\"><div class=\"panel-head\"><h2>Savings goal</h2><span class=\"pill green\">PLAN AHEAD</span></div><form class=\"modal-form\" action=\"/goal\" method=\"post\"><label>Goal name<input name=\"name\" required placeholder=\"Dream trip\"></label><label>Target amount (₹)<input name=\"target_amount\" type=\"number\" step=\"0.01\" min=\"1\" required></label><label>Already saved (₹)<input name=\"saved_amount\" type=\"number\" step=\"0.01\" min=\"0\" value=\"0\"></label><label>Target date<input name=\"target_date\" type=\"date\"></label><button class=\"btn btn-outline\">Create goal</button></form></section></div><section class=\"panel\" id=\"transactions\"><div class=\"panel-head\"><h2>Recent transactions</h2><span class=\"pill\">LATEST ACTIVITY</span></div>%s</section><section class=\"panel\"><div class=\"panel-head\"><h2>Your savings goals</h2><span class=\"pill\">PROGRESS</span></div>%s</section><div class=\"two-col\" id=\"rooms\"><section class=\"panel\"><div class=\"panel-head\"><h2>Create a shared room</h2></div><form class=\"modal-form\" action=\"/room/create\" method=\"post\"><label>Room name<input name=\"name\" required placeholder=\"Flat 3B\"></label><label>Description<input name=\"description\" placeholder=\"Shared household expenses\"></label><button class=\"btn btn-dark\">Create room</button></form></section><section class=\"panel\"><div class=\"panel-head\"><h2>Join a room</h2></div><form class=\"modal-form\" action=\"/room/join\" method=\"post\"><label>Invite code<input name=\"invite_code\" required placeholder=\"Enter room code\"></label><button class=\"btn btn-outline\">Join room</button></form></section></div><section class=\"panel\"><div class=\"panel-head\"><h2>Your shared rooms</h2><span class=\"pill\">TOGETHER</span></div>%s</section></main></div></div><footer class=\"app-footer\">RUPEESENSE · MINDFUL MONEY</footer></body></html>",page_start("Overview"),(int)(unsigned char)full[0],en,*em?em:"",en,ei,ee,eb,today,txhtml,goalhtml,roomhtml);
    free(name);free(full);free(uid);free(today);free(ei);free(ee);free(eb);free(en);free(em);
    if(tx)cJSON_Delete(tx);if(goals)cJSON_Delete(goals);if(members)cJSON_Delete(members);return html;
}
static char *room_page(Session*s,const char *id,const char *notice) {
    char path[2048];long st=0;snprintf(path,sizeof path,"/rest/v1/rooms?id=eq.%s",id);
    cJSON *r=parse_json(supabase(path,"GET",s->token,NULL,NULL,&st));
    if(!cJSON_IsArray(r)||!cJSON_GetArraySize(r)){if(r)cJSON_Delete(r);return dupstr("<h1>Room not found</h1><a href=\"/\">Dashboard</a>");}
    cJSON *room=cJSON_GetArrayItem(r,0);char *rn=json_string(room,"name","Shared room"),*desc=json_string(room,"description","Keep shared spending transparent."),*code=json_string(room,"invite_code","");char *er=html_escape(rn),*ed=html_escape(desc);
    snprintf(path,sizeof path,"/rest/v1/group_expenses?room_id=eq.%s&order=expense_date.desc",id);
    cJSON *ex=parse_json(supabase(path,"GET",s->token,NULL,NULL,&st));char lines[12000]="";
    if(cJSON_IsArray(ex)){cJSON*x=NULL;cJSON_ArrayForEach(x,ex){char*t=json_string(x,"title","Expense"),*cat=json_string(x,"category","Other"),*date=json_string(x,"expense_date","");cJSON*a=cJSON_GetObjectItem(x,"amount");char*m=money(cJSON_IsNumber(a)?a->valuedouble:0),*et=html_escape(t);char l[900];snprintf(l,sizeof l,"<div class=\"transaction-line\"><div class=\"transaction-icon\">◇</div><div class=\"transaction-details\"><b>%s</b><small>%s · %s</small></div><strong>%s</strong></div>",et,cat,date,m);strncat(lines,l,sizeof(lines)-strlen(lines)-1);free(t);free(cat);free(date);free(m);free(et);}}
    if(!*lines)strcpy(lines,"<p class=\"empty-inline\">No shared expenses yet.</p>");
    char *html=calloc(1,25000),*today=get_today(),*em=html_escape(notice?notice:"");
    snprintf(html,25000,"%s<div class=\"app-shell\"><aside class=\"sidebar\"><a class=\"brand\" href=\"/\">₹ RUPEESENSE</a><div class=\"side-label\">YOUR FINANCES</div><nav><a class=\"nav-item\" href=\"/\">◈ &nbsp; Overview</a></nav></aside><div class=\"main-area\"><header class=\"topbar\"><div><div class=\"eyebrow\">SHARED SPACE</div><div class=\"page-title\">%s</div></div><a class=\"btn btn-outline\" href=\"/\">Dashboard</a></header><main class=\"content\"><div class=\"messages\">%s</div><div class=\"welcome-row\"><div><div class=\"eyebrow\">SHARED SPACE</div><h1>%s</h1><p class=\"muted\">%s</p><p class=\"invite\">INVITE CODE &nbsp; <strong>%s</strong></p></div></div><div class=\"two-col\"><section class=\"panel\"><div class=\"panel-head\"><h2>Add group expense</h2><span class=\"pill\">SHARED</span></div><p class=\"muted\">Expenses are split equally between current room members.</p><form class=\"modal-form\" action=\"/room/%s/expense\" method=\"post\"><label>Expense name<input name=\"title\" required placeholder=\"Groceries\"></label><label>Amount (₹)<input type=\"number\" name=\"amount\" min=\"0.01\" step=\"0.01\" required></label><label>Category<input name=\"category\" value=\"Other\"></label><label>Date<input type=\"date\" name=\"expense_date\" value=\"%s\"></label><button class=\"btn btn-dark\">Add expense & split</button></form></section><section class=\"panel\"><div class=\"panel-head\"><h2>Room members</h2></div><p class=\"empty-inline\">Member access is managed by your Supabase room_members table.</p></section></div><section class=\"panel\"><div class=\"panel-head\"><h2>Group expenses</h2><span class=\"pill\">ROOM ACTIVITY</span></div>%s</section></main></div></div></body></html>",page_start("Shared room"),er,em,er,ed,code,id,today,lines);
    free(rn);free(desc);free(code);free(er);free(ed);free(today);free(em);if(r)cJSON_Delete(r);if(ex)cJSON_Delete(ex);return html;
}

static enum MHD_Result handler(void *cls,struct MHD_Connection *con,const char *url,const char *method,
 const char *version,const char *upload_data,size_t *upload_data_size,void **con_cls) {
    (void)cls;(void)version;
    if(!strcmp(url,"/style.css")) {
        FILE*f=fopen("static/style.css","rb");if(!f)return MHD_NO;fseek(f,0,SEEK_END);long n=ftell(f);rewind(f);char*b=malloc(n+1);fread(b,1,n,f);b[n]=0;fclose(f);
        struct MHD_Response*r=MHD_create_response_from_buffer(n,b,MHD_RESPMEM_MUST_FREE);MHD_add_response_header(r,"Content-Type","text/css");enum MHD_Result z=MHD_queue_response(con,200,r);MHD_destroy_response(r);return z;
    }
    Form *form=*con_cls;
    if(!form){form=calloc(1,sizeof(Form));form->body=calloc(1,1);*con_cls=form;return MHD_YES;}
    if(!strcmp(method,"POST")&&*upload_data_size){size_t n=*upload_data_size;if(form->len+n<MAX_BODY){form->body=realloc(form->body,form->len+n+1);memcpy(form->body+form->len,upload_data,n);form->len+=n;form->body[form->len]=0;}*upload_data_size=0;return MHD_YES;}
    Session *s=session_for(con); char *notice=NULL;
    if(!strcmp(url,"/auth")&&!strcmp(method,"POST")) {
        char *mode=form_get(form->body,"mode"),*email=form_get(form->body,"email"),*pass=form_get(form->body,"password"),*full=form_get(form->body,"full_name");
        cJSON *j=cJSON_CreateObject();cJSON_AddStringToObject(j,"email",email);cJSON_AddStringToObject(j,"password",pass);
        if(!strcmp(mode,"signup")){cJSON *d=cJSON_CreateObject();cJSON_AddStringToObject(d,"full_name",full);cJSON_AddItemToObject(j,"data",d);}
        char *payload=json_print(j);cJSON_Delete(j);long st=0;char *res=supabase(!strcmp(mode,"signup")?"/auth/v1/signup":"/auth/v1/token?grant_type=password","POST",NULL,payload,NULL,&st);free(payload);
        cJSON *a=cJSON_Parse(res);free(res);cJSON *tok=cJSON_GetObjectItem(a,"access_token"),*user=cJSON_GetObjectItem(a,"user");
        if(cJSON_IsString(tok)&&cJSON_IsObject(user)){Session*ns=new_session();snprintf(ns->token,sizeof ns->token,"%s",tok->valuestring);ns->user=cJSON_Duplicate(user,1);char cookie[200];snprintf(cookie,sizeof cookie,"rsid=%s; Path=/; HttpOnly; SameSite=Lax",ns->sid);if(a)cJSON_Delete(a);return redirect_to(con,"/",cookie);}
        notice=dupstr("Sign in or account creation failed. Check your details and Supabase configuration.");
        if(a)cJSON_Delete(a);char *out=auth_page(notice);enum MHD_Result z=respond(con,out,200,NULL);free(out);free(notice);return z;
    }
    if(!strcmp(url,"/logout")){if(s)clear_session(s);return redirect_to(con,"/","rsid=; Path=/; Max-Age=0; HttpOnly; SameSite=Lax");}
    if(!s||!s->user){char*out=auth_page("");enum MHD_Result z=respond(con,out,200,NULL);free(out);return z;}
    if(!strcmp(url,"/transaction")&&!strcmp(method,"POST")) {
        char *type=form_get(form->body,"type"),*title=form_get(form->body,"title"),*amount=form_get(form->body,"amount"),*cat=form_get(form->body,"category"),*date=form_get(form->body,"txn_date"),*pay=form_get(form->body,"payment_method"),*desc=form_get(form->body,"description"),*uid=json_string(s->user,"id","");
        cJSON*j=cJSON_CreateObject();cJSON_AddStringToObject(j,"user_id",uid);cJSON_AddStringToObject(j,"type",type);cJSON_AddStringToObject(j,"title",title);cJSON_AddNumberToObject(j,"amount",atof(amount));cJSON_AddStringToObject(j,"category",*cat?cat:"Other");cJSON_AddStringToObject(j,"txn_date",*date?date:get_today());cJSON_AddStringToObject(j,"payment_method",*pay?pay:"Other");if(*desc)cJSON_AddStringToObject(j,"description",desc);
        char*b=json_print(j);cJSON_Delete(j);long st=0;char*r=supabase("/rest/v1/personal_transactions","POST",s->token,b,"return=representation",&st);free(r);free(b);notice=dupstr(st>=200&&st<300?"Transaction added!":"Could not save transaction.");free(type);free(title);free(amount);free(cat);free(date);free(pay);free(desc);free(uid);
    } else if(!strcmp(url,"/goal")&&!strcmp(method,"POST")) {
        char *n=form_get(form->body,"name"),*t=form_get(form->body,"target_amount"),*sv=form_get(form->body,"saved_amount"),*dt=form_get(form->body,"target_date"),*uid=json_string(s->user,"id","");
        cJSON*j=cJSON_CreateObject();cJSON_AddStringToObject(j,"user_id",uid);cJSON_AddStringToObject(j,"name",n);cJSON_AddNumberToObject(j,"target_amount",atof(t));cJSON_AddNumberToObject(j,"saved_amount",atof(sv));if(*dt)cJSON_AddStringToObject(j,"target_date",dt);
        char*b=json_print(j);cJSON_Delete(j);long st=0;char*r=supabase("/rest/v1/savings_goals","POST",s->token,b,"return=representation",&st);free(r);free(b);notice=dupstr(st>=200&&st<300?"Savings goal created!":"Could not create savings goal.");free(n);free(t);free(sv);free(dt);free(uid);
    } else if(!strcmp(url,"/room/create")&&!strcmp(method,"POST")) {
        char *n=form_get(form->body,"name"),*d=form_get(form->body,"description"),*uid=json_string(s->user,"id","");char code[16];snprintf(code,sizeof code,"%06X",(unsigned)(random()&0xffffff));
        cJSON*j=cJSON_CreateObject();cJSON_AddStringToObject(j,"name",n);cJSON_AddStringToObject(j,"description",d);cJSON_AddStringToObject(j,"created_by",uid);cJSON_AddStringToObject(j,"invite_code",code);cJSON_AddStringToObject(j,"room_type","Shared living");
        char*b=json_print(j);cJSON_Delete(j);long st=0;char*r=supabase("/rest/v1/rooms","POST",s->token,b,"return=representation",&st);cJSON*a=cJSON_Parse(r);free(r);free(b);
        cJSON*room=cJSON_IsArray(a)?cJSON_GetArrayItem(a,0):NULL;char*rid=json_string(room,"id","");
        if(*rid){cJSON*m=cJSON_CreateObject();cJSON_AddStringToObject(m,"room_id",rid);cJSON_AddStringToObject(m,"user_id",uid);cJSON_AddStringToObject(m,"role","owner");b=json_print(m);cJSON_Delete(m);r=supabase("/rest/v1/room_members","POST",s->token,b,"return=representation",&st);free(r);free(b);}
        char msg[128];snprintf(msg,sizeof msg,"Room created! Invite code: %s",code);notice=dupstr(msg);free(rid);if(a)cJSON_Delete(a);free(n);free(d);free(uid);
    } else if(!strcmp(url,"/room/join")&&!strcmp(method,"POST")) {
        char *code=form_get(form->body,"invite_code");for(char*p=code;*p;p++)*p=(char)toupper((unsigned char)*p);
        cJSON*j=cJSON_CreateObject();cJSON_AddStringToObject(j,"p_code",code);char*b=json_print(j);cJSON_Delete(j);long st=0;char*r=supabase("/rest/v1/rpc/join_room_by_code","POST",s->token,b,NULL,&st);free(r);free(b);notice=dupstr(st>=200&&st<300?"Joined room successfully!":"Could not join room. Check the invite code.");free(code);
    } else if(strstr(url,"/room/")&&strstr(url,"/expense")&&!strcmp(method,"POST")) {
        char *id=strdup(url+6);char *slash=strstr(id,"/expense");if(slash)*slash=0;
        char *title=form_get(form->body,"title"),*amount=form_get(form->body,"amount"),*cat=form_get(form->body,"category"),*date=form_get(form->body,"expense_date"),*uid=json_string(s->user,"id","");
        char path[1024];snprintf(path,sizeof path,"/rest/v1/room_members?room_id=eq.%s&select=user_id",id);long st=0;cJSON*members=parse_json(supabase(path,"GET",s->token,NULL,NULL,&st));
        cJSON*j=cJSON_CreateObject();cJSON_AddStringToObject(j,"room_id",id);cJSON_AddStringToObject(j,"created_by",uid);cJSON_AddStringToObject(j,"paid_by",uid);cJSON_AddStringToObject(j,"title",title);cJSON_AddNumberToObject(j,"amount",atof(amount));cJSON_AddStringToObject(j,"category",*cat?cat:"Other");cJSON_AddStringToObject(j,"expense_date",*date?date:get_today());cJSON_AddStringToObject(j,"split_type","equal");
        char*b=json_print(j);cJSON_Delete(j);char*r=supabase("/rest/v1/group_expenses","POST",s->token,b,"return=representation",&st);cJSON*ex=cJSON_Parse(r);free(r);free(b);
        cJSON*e=cJSON_IsArray(ex)?cJSON_GetArrayItem(ex,0):NULL;char*eid=json_string(e,"id","");
        if(*eid&&cJSON_IsArray(members)&&cJSON_GetArraySize(members)>0){double total=atof(amount),each=total/cJSON_GetArraySize(members);cJSON*rows=cJSON_CreateArray();int count=cJSON_GetArraySize(members),i=0;cJSON*m=NULL;cJSON_ArrayForEach(m,members){char*mid=json_string(m,"user_id","");cJSON*row=cJSON_CreateObject();cJSON_AddStringToObject(row,"expense_id",eid);cJSON_AddStringToObject(row,"user_id",mid);cJSON_AddNumberToObject(row,"amount",i++==count-1?total-each*(count-1):each);cJSON_AddItemToArray(rows,row);free(mid);}b=json_print(rows);cJSON_Delete(rows);r=supabase("/rest/v1/expense_splits","POST",s->token,b,"return=representation",&st);free(r);free(b);}
        notice=dupstr(st>=200&&st<300?"Group expense saved and split equally.":"Could not save group expense.");if(members)cJSON_Delete(members);if(ex)cJSON_Delete(ex);free(eid);free(id);free(title);free(amount);free(cat);free(date);free(uid);
    }
    char *out=NULL;
    if(!strncmp(url,"/room/",6)&&strcmp(url,"/room/create")&&strcmp(url,"/room/join")) {char *id=strdup(url+6);char *slash=strchr(id,'/');if(slash)*slash=0;out=room_page(s,id,notice);free(id);}
    else out=make_dashboard(s,notice);
    enum MHD_Result z=respond(con,out,200,NULL);free(out);if(notice)free(notice);
    if(form){free(form->body);free(form);*con_cls=NULL;}return z;
}
int main(void) {
    SUPABASE_URL=envv("SUPABASE_URL","");SUPABASE_KEY=envv("SUPABASE_ANON_KEY","");
    PORT=(char*)envv("PORT","8080");srandom((unsigned)time(NULL));curl_global_init(CURL_GLOBAL_DEFAULT);
    if(!*SUPABASE_URL||!*SUPABASE_KEY)fprintf(stderr,"WARNING: Set SUPABASE_URL and SUPABASE_ANON_KEY before using Supabase features.\\n");
    struct MHD_Daemon*d=MHD_start_daemon(MHD_USE_INTERNAL_POLLING_THREAD,atoi(PORT),NULL,NULL,&handler,NULL,MHD_OPTION_NOTIFY_COMPLETED,NULL,NULL,MHD_OPTION_END);
    if(!d){fprintf(stderr,"Could not start HTTP server.\\n");return 1;}
    printf("RupeeSense C server listening on port %s\\n",PORT);while(1)sleep(3600);
    MHD_stop_daemon(d);curl_global_cleanup();return 0;
}
