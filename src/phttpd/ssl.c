/* ====================================================================
 * Copyright (c) 1995, 1996, 1997 Ben Laurie.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer. 
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by Ben Laurie
 *    for use in the Apache-SSL HTTP server project."
 *
 * 4. The name "Apache-SSL Server" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission.
 *
 * 5. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by Ben Laurie
 *    for use in the Apache-SSL HTTP server project."
 *
 * THIS SOFTWARE IS PROVIDED BY BEN LAURIE ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL BEN LAURIE OR
 * HIS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This software consists of patches to the Apache HTTP server interfacing it
 * to SSLeay.
 * For more information on Apache-SSL, contact Ben Laurie <ben@algroup.co.uk>.
 *
 * For more information on Apache see http://www.apache.org.
 *
 * For more information on SSLeay see http://www.psy.uq.oz.au/~ftp/Crypto/.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <assert.h>

#include <ssl.h>
#include <err.h>
#include <x509.h>
#include <pem.h>
#include <crypto.h>

#include "httpd.h"
#include "http_config.h"
#include "http_log.h"

#if SSLEAY_VERSION_NUMBER < 0x600
#define ERR_print_errors_fp	ERR_print_errors
#endif

#if SSLEAY_VERSION_NUMBER < 0x0800
#define X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY \
		VERIFY_ERR_UNABLE_TO_GET_ISSUER
#define X509_V_OK VERIFY_OK
#define SSL_CTX_set_default_verify_paths(ctx) SSL_set_default_verify_paths(ctx)
#define SSL_CTX_load_verify_locations(ctx,cafile,capath) \
		 SSL_load_verify_locations(ctx,cafile,capath)
#define X509_verify_cert_error_string(error) X509_cert_verify_error_string(error)
#endif

#if !defined(SSL_TXT_NULL)
/* text strings for the ciphers */
#define SSL_TXT_NULL_WITH_MD5		SSL2_TXT_NULL_WITH_MD5
#define SSL_TXT_RC4_128_WITH_MD5	SSL2_TXT_RC4_128_WITH_MD5
#define SSL_TXT_RC4_128_EXPORT40_WITH_MD5	SSL2_TXT_RC4_128_EXPORT40_WITH_MD5
#define SSL_TXT_RC2_128_CBC_WITH_MD5	SSL2_TXT_RC2_128_CBC_WITH_MD5
#define SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5	SSL2_TXT_RC2_128_CBC_EXPORT40_WITH_MD5
#define SSL_TXT_IDEA_128_CBC_WITH_MD5	SSL2_TXT_IDEA_128_CBC_WITH_MD5
#define SSL_TXT_DES_64_CBC_WITH_MD5	SSL2_TXT_DES_64_CBC_WITH_MD5
#define SSL_TXT_DES_64_CBC_WITH_SHA	SSL2_TXT_DES_64_CBC_WITH_SHA
#define SSL_TXT_DES_192_EDE3_CBC_WITH_MD5	SSL2_TXT_DES_192_EDE3_CBC_WITH_MD5
#define SSL_TXT_DES_192_EDE3_CBC_WITH_SHA	SSL2_TXT_DES_192_EDE3_CBC_WITH_SHA

#define SSL_TXT_DES_64_CFB64_WITH_MD5_1	SSL2_TXT_DES_64_CFB64_WITH_MD5_1
#define SSL_TXT_NULL			SSL2_TXT_NULL
#endif

#ifndef SSL_TXT_DES_64_CFB64_WITH_MD5_1
/* SSLeay 0.8.0 misses this definition */
#define SSL_TXT_DES_64_CFB64_WITH_MD5_1	SSL2_TXT_DES_64_CFB64_WITH_MD5_1
#endif

typedef enum
    {
    VERIFY_NONE=0,
    VERIFY_OPTIONAL=1,
    VERIFY_REQUIRE=2,
    VERIFY_OPTIONAL_NO_CA=3
    } VerifyType;

typedef struct
    {
    BOOL bDisabled;

    char *szCertificateFile;
    char *szKeyFile;
    char *szCACertificatePath;
    char *szCACertificateFile;
    char *szLogFile;
    char *szReqCiphers;
    FILE *fileLogFile;
    int nVerifyDepth;
    VerifyType nVerifyClient;

    X509 *px509Certificate;
    RSA *prsaKey;

    SSL_CTX *pSSLCtx;

    BOOL bFakeBasicAuth;
    } SSLConfigRec;

typedef struct
    {
    /* 1) If cipher is banned, refuse */
    /* 2) If RequiredCiphers is NULL, accept */
    /* 3) If the cipher isn't required, refuse */

    table *tbRequiredCiphers;
    table *tbBannedCiphers;
    } SSLDirConfigRec;

extern module ssl_module;

static conn_rec *SSLVerifyConn;

static const char *SSLRequireCipher(cmd_parms *cmd,SSLDirConfigRec *rec,char *cipher)
    {
    table_set(rec->tbRequiredCiphers,cipher,"Required");
    return NULL;
    }

static const char *SSLBanCipher(cmd_parms *cmd,SSLDirConfigRec *rec,char *cipher)
    {
    table_set(rec->tbBannedCiphers,cipher,"Banned");
    return NULL;
    }

static int SSLCheckCipher(request_rec *r)
    {
    char *cipher;
    SSLDirConfigRec *rec=(SSLDirConfigRec *)
      get_module_config(r->per_dir_config,&ssl_module);
    SSLConfigRec *pConfig=(SSLConfigRec *)
      get_module_config(r->server->module_config,&ssl_module);

    /* Check to see if SSL is on */
    if(pConfig->bDisabled)
	return DECLINED;

    cipher=SSL_get_cipher(r->connection->client->ssl);

    if(table_get(rec->tbBannedCiphers,cipher))
	{
	char *buf;

	buf=pstrcat(r->pool,"Cipher ",cipher," is forbidden",NULL);
	log_reason(buf,r->filename,r);
	return FORBIDDEN;
	}
    if(table_get(rec->tbRequiredCiphers,cipher))
	return OK;

    if(rec->tbRequiredCiphers->nelts == 0)
	return OK;
    else
	{
	char *buf;
	
	buf=pstrcat(r->pool,"Cipher ",cipher," is not on the permitted list",
		    NULL);
	log_reason(buf,r->filename,r);
	return FORBIDDEN;
	}
    }

int SSLFixups (request_rec *r)
    {
    table *e=r->subprocess_env;
    int keysize=0;
    int secretkeysize=0;
    char buf[MAX_STRING_LEN];
    char *cipher;

    SSLConfigRec *pConfig=(SSLConfigRec *)
      get_module_config(r->server->module_config,&ssl_module);

    /* Check to see if SSL is on */
    if(pConfig->bDisabled)
	return DECLINED;

    cipher=SSL_get_cipher(r->connection->client->ssl);
    table_set(e,"HTTPS","on");
    table_set(e,"HTTPS_CIPHER",cipher);

    if(!strcmp(cipher,SSL_TXT_NULL_WITH_MD5))
	keysize=secretkeysize=0;
    else if(!strcmp(cipher,SSL_TXT_RC4_128_WITH_MD5))
	keysize=secretkeysize=128;
    else if(!strcmp(cipher,SSL_TXT_RC4_128_EXPORT40_WITH_MD5))
	{ keysize=128; secretkeysize=40; }
    else if(!strcmp(cipher,SSL_TXT_RC2_128_CBC_WITH_MD5))
	keysize=secretkeysize=128;
    else if(!strcmp(cipher,SSL_TXT_RC2_128_CBC_EXPORT40_WITH_MD5))
	{ keysize=128; secretkeysize=40; }
    else if(!strcmp(cipher,SSL_TXT_IDEA_128_CBC_WITH_MD5))
	keysize=secretkeysize=128;
    else if(!strcmp(cipher,SSL_TXT_DES_64_CBC_WITH_MD5))
	keysize=secretkeysize=64;
    else if(!strcmp(cipher,SSL_TXT_DES_64_CBC_WITH_SHA))
	keysize=secretkeysize=64;
    else if(!strcmp(cipher,SSL_TXT_DES_192_EDE3_CBC_WITH_MD5))
	keysize=secretkeysize=192;
    else if(!strcmp(cipher,SSL_TXT_DES_192_EDE3_CBC_WITH_SHA))
	keysize=secretkeysize=192;
    else if(!strcmp(cipher,SSL_TXT_DES_64_CFB64_WITH_MD5_1))
	keysize=secretkeysize=64;
    else if(!strcmp(cipher,SSL_TXT_NULL))
	keysize=secretkeysize=0;

    sprintf(buf,"%d",keysize);
    table_set(e,"HTTPS_KEYSIZE",buf);

    sprintf(buf,"%d",secretkeysize);
    table_set(e,"HTTPS_SECRETKEYSIZE",buf);

    if(r->connection->client->szClientX509)
	table_set(e,"SSL_CLIENT_DN",r->connection->client->szClientX509);

    return OK;
    }

static void SSLLogError(server_rec *s)
    {
    unsigned long l;
    char buf[MAX_STRING_LEN];

    /* Print out error messages */

    while((l=ERR_get_error()))
      {
	ERR_error_string(l,buf);
	log_error(buf,s);
      }
    }

static void *CreateSSLServerConfig(pool *p,server_rec *s)
    {
    SSLConfigRec *rec=pcalloc(p,sizeof(SSLConfigRec));
    
    rec->bDisabled=FALSE;
    rec->szCertificateFile=rec->szKeyFile=rec->szLogFile=NULL;
    rec->nVerifyDepth=0;
    rec->nVerifyClient=VERIFY_NONE;
    rec->px509Certificate=NULL;
    rec->prsaKey=NULL;
    rec->bFakeBasicAuth=FALSE;
    return rec;
    }

static void *CreateSSLDirConfig(pool *p,char *dummy)
    {
    SSLDirConfigRec *rec=pcalloc(p,sizeof(SSLDirConfigRec));

    rec->tbRequiredCiphers=make_table(p,4);
    rec->tbBannedCiphers=make_table(p,4);

    return rec;
    }

static void *MergeSSLDirConfig(pool *p,void *basev,void *addv)
    {
    SSLDirConfigRec *base=(SSLDirConfigRec *)basev;
    SSLDirConfigRec *add=(SSLDirConfigRec *)addv;
    SSLDirConfigRec *new=(SSLDirConfigRec *)palloc(p,sizeof(SSLDirConfigRec));

    new->tbRequiredCiphers=overlay_tables(p,add->tbRequiredCiphers,
					    base->tbRequiredCiphers);
    new->tbBannedCiphers=overlay_tables(p,add->tbBannedCiphers,
					  base->tbBannedCiphers);
    return new;
    }

static void InitSSL()
    {
    char *CAfile=NULL,*CApath=NULL;

    SSL_load_error_strings();
    ERR_load_crypto_strings();
#if SSLEAY_VERSION_NUMBER >= 0x0800
    SSLeay_add_ssl_algorithms();
#else
    SSL_debug("/tmp/ssldebug");
#endif
    }

#if SSLEAY_VERSION_NUMBER >= 0x0800
/* FIXME: This is an expensive operation which should probably be done before
forking */
static RSA *TmpRSACallback(SSL *pSSL,int nExport)
    {
    static RSA *pRSA=NULL;

    if (pRSA == NULL)
	pRSA=RSA_generate_key(512,RSA_F4,NULL);
    return pRSA;
    }
#endif

#if SSLEAY_VERSION_NUMBER >= 0x0800
int ApacheSSLVerifyCallback(int ok,X509_STORE_CTX *ctx)
    {
    X509 *xs=X509_STORE_CTX_get_current_cert(ctx);
    int depth=X509_STORE_CTX_get_error_depth(ctx);
    int error=X509_STORE_CTX_get_error(ctx);
#else
int ApacheSSLVerifyCallback(int ok,X509 *xs,X509 *xi,int depth,int error)
    {
#endif
    char *s;
    SSLConfigRec *pConfig=get_module_config(SSLVerifyConn->server->module_config,&ssl_module);

#if SSLEAY_VERSION_NUMBER < 0x0800
    s=(char *)X509_NAME_oneline(X509_get_subject_name(xs));
#else
    s=(char *)X509_NAME_oneline(X509_get_subject_name(xs),NULL,0);
#endif

    if(s == NULL)
	{
	ERR_print_errors_fp(pConfig->fileLogFile);
	return(0);
	}
    if(depth == 0)
	SSLVerifyConn->client->szClientX509=pstrdup(SSLVerifyConn->pool,s);

    fprintf(pConfig->fileLogFile,"depth=%d %s\n",depth,s);
    free(s);
    if(error == X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT_LOCALLY)
	{
	if(pConfig->nVerifyClient == VERIFY_OPTIONAL_NO_CA)
	    {
	    fprintf(pConfig->fileLogFile,"no issuer, returning OK\n");
	    return TRUE;
	    }
#if SSLEAY_VERSION_NUMBER < 0x0800
	s=(char *)X509_NAME_oneline(X509_get_issuer_name(xs));
#else
	s=(char *)X509_NAME_oneline(X509_get_issuer_name(xs),NULL,0);
#endif
	if(s == NULL)
	    {
	    fprintf(pConfig->fileLogFile,"verify error\n");
	    ERR_print_errors_fp(pConfig->fileLogFile);
	    SSLLogError(SSLVerifyConn->server);
	    return(0);
	    }
	fprintf(pConfig->fileLogFile,"issuer= %s\n",s);
	free(s);
	}
    if(!ok)
	{
	fprintf(pConfig->fileLogFile,"verify error:num=%d:%s\n",error,
		X509_verify_cert_error_string(error));
	SSLLogError(SSLVerifyConn->server);
	SSLVerifyConn->client->szClientX509=NULL;
	}
    if(depth >= pConfig->nVerifyDepth)
	{
	fprintf(pConfig->fileLogFile,"Verify depth exceeded\n");
	log_error("Verify depth exceeded",SSLVerifyConn->server);
	ok=0;
	}
    fprintf(pConfig->fileLogFile,"verify return:%d\n",ok);
    return(ok);
    }

static int VerifyFlags(SSLConfigRec *pConfig)
    {
    int nVerify=0;

    switch(pConfig->nVerifyClient)
	{
    case VERIFY_REQUIRE:
	nVerify|=SSL_VERIFY_PEER|SSL_VERIFY_FAIL_IF_NO_PEER_CERT;
	break;

    case VERIFY_OPTIONAL:
    case VERIFY_OPTIONAL_NO_CA:
	nVerify|=SSL_VERIFY_PEER;
	break;
	}
    return nVerify;
    }

static void GetCertificateAndKey(server_rec *s,SSLConfigRec *pConfig)
    {
    char buf[1024],prompt[1024];
    int n;
    FILE *f;
    char szPath[MAX_STRING_LEN];


    if(pConfig->px509Certificate)
	{
	fprintf(stderr,"Attempt to reinitialise SSL for server %s\n",
		s->server_hostname);
	return;
	}

    fprintf(stderr,"Reading certificate and key for server %s:%d\n",
	    s->server_hostname,s->port);

#if SSLEAY_VERSION_NUMBER < 0x0800
    pConfig->pSSLCtx=SSL_CTX_new();
#else
    pConfig->pSSLCtx=SSL_CTX_new(SSLv23_server_method());
    SSL_CTX_set_verify(pConfig->pSSLCtx,VerifyFlags(pConfig),ApacheSSLVerifyCallback);
#endif

    if(pConfig->szReqCiphers != NULL)
	{
	if(!SSL_CTX_set_cipher_list(pConfig->pSSLCtx,pConfig->szReqCiphers))
	    {
	    fprintf(stderr,"unable to set ciphers\n");
	    ERR_print_errors_fp(stderr);
	    SSLLogError(s);
	    }
	}

    if(!SSL_CTX_load_verify_locations(pConfig->pSSLCtx,
				  pConfig->szCACertificateFile,
				  pConfig->szCACertificatePath)
       || !SSL_CTX_set_default_verify_paths(pConfig->pSSLCtx))
       {
       fprintf(stderr,"error seting default verify locations\n");
       ERR_print_errors_fp(stderr);
       exit(1);
       }

    f=fopen(pConfig->szCertificateFile,"r");
    if(!f)
	{
	sprintf(szPath,"%s/%s",X509_get_default_cert_dir(),
		pConfig->szCertificateFile);
	f=fopen(szPath,"r");
	if(!f)
	    {
	    fprintf(stderr,"Can't open certificate file %s, nor %s\n",
		    pConfig->szCertificateFile,szPath);
	    exit(1);
	    }
	}
    else
	strcpy(szPath,pConfig->szCertificateFile);  /* in case it also contains the key */

    pConfig->px509Certificate=X509_new();

    if(!PEM_read_X509(f,&pConfig->px509Certificate,NULL))
	{
	fprintf(stderr,"Error reading server certificate file %s: ",szPath);
	ERR_print_errors_fp(stderr);
	exit(1);
	}
    fclose(f);

    if(pConfig->szKeyFile)
	if(*pConfig->szKeyFile == '/')
	    strcpy(szPath,pConfig->szKeyFile);
	else
	    sprintf(szPath,"%s/private/%s",X509_get_default_cert_area(),
		    pConfig->szKeyFile);

/* Otherwise the path already contains the name of the certificate file */
    f=fopen(szPath,"r");
    if(!f)
	{
	fprintf(stderr,"Can't open key file ");
	perror(szPath);
	exit(1);
	}

    pConfig->prsaKey=RSA_new();
    if(!PEM_read_RSAPrivateKey(f,&pConfig->prsaKey,NULL))
	{
	fprintf(stderr,"Error reading private key file %s: ",szPath);
	ERR_print_errors_fp(stderr);
	exit(1);
	}

#if SSLEAY_VERSION_NUMBER >= 0x0800
    SSL_CTX_set_tmp_rsa_callback(pConfig->pSSLCtx,TmpRSACallback);
    /* Really this should have its own directive and list, but I haven't got
       the time at the moment.
     */
    SSL_CTX_set_client_CA_list(pConfig->pSSLCtx, 
	    SSL_load_client_CA_file(pConfig->szCACertificateFile)); 
#endif
    }

static void InitSSLServer(server_rec *s,pool *p)
    {
    InitSSL();
    for ( ; s ; s=s->next)
	{
	SSLConfigRec *pConfig=get_module_config(s->module_config,&ssl_module);

	if(pConfig->bDisabled)
	    {
	    if(!s->port)
		s->port=HTTP_PORT;
	    fprintf(stderr,"SSL disabled for server %s:%d\n",
		    s->server_hostname,s->port);
	    continue;
	    }

	if(!s->port)
	    s->port=HTTPS_PORT;

	if(!pConfig->szCertificateFile)
	    {
	    fprintf(stderr,"No SSL Certificate set for server %s:%d\n",
		    s->server_hostname,s->port);
	    exit(1);
	    }
	if(pConfig->nVerifyClient < 0 || pConfig->nVerifyClient > VERIFY_OPTIONAL_NO_CA)
	    {
	    fprintf(stderr,"Bad value for SSLVerifyClient (%d)\n",pConfig->nVerifyClient);
	    exit(1);
	    }
	if(!pConfig->szLogFile)
	    {
	    fprintf(stderr,"Required SSLLogFile missing\n");
	    exit(1);
	    }
	
	pConfig->fileLogFile=fopen(pConfig->szLogFile,"a");
	if(!pConfig->fileLogFile)
	    {
	    perror(pConfig->szLogFile);
	    exit(1);
	    }
	setbuf(pConfig->fileLogFile,NULL);
    
	GetCertificateAndKey(s,pConfig);
	}
    }

static const char *set_server_string_slot (cmd_parms *cmd,char *struct_ptr,char *arg)
    {
    /* This one should be pretty generic... */
    char *pConfig=get_module_config(cmd->server->module_config,&ssl_module);
  
    int offset=(int)cmd->info; 
    *(char **)(pConfig+offset)=arg;
    return NULL;
    }

static const char *set_server_int_slot (cmd_parms *cmd,char *struct_ptr,char *arg)
    {
  /* This one should be pretty generic... */
    char *pConfig=get_module_config(cmd->server->module_config,&ssl_module);
  
    int offset=(int)cmd->info; 
    *(int *)(pConfig+offset)=atoi(arg);
    return NULL;
    }

static const char *set_server_bool_slot (cmd_parms *cmd,char *struct_ptr)
    {
  /* This one should be pretty generic... */
    char *pConfig=get_module_config(cmd->server->module_config,&ssl_module);
  
    int offset=(int)cmd->info; 
    *(BOOL *)(pConfig+offset)=TRUE;
    return NULL;
    }

command_rec ssl_cmds[]=
    {
    { "SSLDisable",set_server_bool_slot,
      (void *)XtOffsetOf(SSLConfigRec,bDisabled),RSRC_CONF,NO_ARGS,
      "Enable SSL" },
    { "SSLCertificateFile",set_server_string_slot,
      (void *)XtOffsetOf(SSLConfigRec,szCertificateFile),RSRC_CONF,TAKE1,
      "PEM certificate file" },
    { "SSLCertificateKeyFile",set_server_string_slot,
      (void *)XtOffsetOf(SSLConfigRec,szKeyFile),RSRC_CONF,TAKE1,
      "Certificate private key file (assumed to be SSLCertificateFile if absent)" },
    { "SSLCACertificatePath",set_server_string_slot,
      (void *)XtOffsetOf(SSLConfigRec,szCACertificatePath),RSRC_CONF,TAKE1,
      "CA Certificate path (taken from SSL_CERT_DIR if absent)" },
    { "SSLCACertificateFile",set_server_string_slot,
      (void *)XtOffsetOf(SSLConfigRec,szCACertificateFile),RSRC_CONF,TAKE1,
      "CA Certificate file (taken from SSL_CERT_FILE if absent)" },
    { "SSLVerifyDepth",set_server_int_slot,
      (void *)XtOffsetOf(SSLConfigRec,nVerifyDepth),RSRC_CONF,TAKE1,
      "Verify depth (default 0)" },
    { "SSLVerifyClient",set_server_int_slot,
      (void *)XtOffsetOf(SSLConfigRec,nVerifyClient),RSRC_CONF,TAKE1,
      "Verify client (0=no,1=optional,2=required" },
    { "SSLFakeBasicAuth",set_server_bool_slot,
      (void *)XtOffsetOf(SSLConfigRec,bFakeBasicAuth),RSRC_CONF,NO_ARGS,
      "Translate client X509 into a user name" },
    { "SSLLogFile",set_server_string_slot,
      (void *)XtOffsetOf(SSLConfigRec,szLogFile),RSRC_CONF,TAKE1,
      "Place to dump all SSL messages that have no better home" },
    { "SSLRequiredCiphers",set_server_string_slot,
      (void *)XtOffsetOf(SSLConfigRec,szReqCiphers),RSRC_CONF,TAKE1,
      "Colon-delimited list of required ciphers" },
    /* Per Directory */
    { "SSLRequireCipher",SSLRequireCipher,NULL,OR_FILEINFO,ITERATE,
      "add a cipher to the per directory list of required ciphers" },
    { "SSLBanCipher",SSLBanCipher,NULL,OR_FILEINFO,ITERATE,
      "add a cipher to the per directory list of banned ciphers" },
    { NULL },
    };

static const char six2pr[64+1]=
  "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

void uuencode(char *szTo,const char *szFrom)
    {
    const unsigned char *s;

    for(s=(const unsigned char *)szFrom ; *s ; s+=3)
	{
	*szTo++=six2pr[s[0] >> 2];
	*szTo++=six2pr[(s[0] << 4 | s[1] >> 4)&0x3f];
	if(!s[0])
	    break;
	*szTo++=six2pr[(s[1] << 2 | s[2] >> 6)&0x3f];
	if(!s[1])
	    break;
	*szTo++=six2pr[s[2]&0x3f];
	if(!s[2])
	    break;
	}
    *szTo++='\0';
    }

/*
Fake a Basic authentication from the X509 client certificate.

This must be run fairly early on to prevent a real authentication from
occuring, in particular it must be run before anything else that authenticates
a user.

This means that the Module statement for this module should be LAST in the
Configuration file.
*/

static int FakeBasicAuth(request_rec *r)
    {
    SSLConfigRec *pConfig=get_module_config(r->server->module_config,&ssl_module);
    char b1[MAX_STRING_LEN],b2[MAX_STRING_LEN];
  
    if(!pConfig->bFakeBasicAuth)
	return DECLINED;
    if(r->connection->user)
	return DECLINED;
    if(!r->connection->client->szClientX509)
	return DECLINED;
    /*
       Fake a password - which one would be immaterial, as, it seems, an empty
       password in the users file would match ALL incoming passwords, if only we
       were using the standard crypt library routine. Unfortunately, SSLeay
       "fixes" a "bug" in crypt and thus prevents blank passwords from working.
       (IMHO what they really fix is a bug in the users of the code - failing to
       program correctly for shadow passwords).
       We need, therefore, to provide a password. This password can be matched by
       adding the string "xxj31ZMTZzkVA" as the password in the user file.
*/
    sprintf(b1,"%s:password",r->connection->client->szClientX509);
    uuencode(b2,b1);
    sprintf(b1,"Basic %s",b2);
    table_set(r->headers_in,"Authorization",b1);
    return DECLINED;
    }

static BOOL ApacheSSLSetCertStuff(conn_rec *conn)
    {
    SSLConfigRec *pConfig=get_module_config(conn->server->module_config,
					    &ssl_module);
    SSL *con=conn->client->ssl;
    char *cert_file=pConfig->szCertificateFile;
    char *key_file=pConfig->szKeyFile;

/*  PEM_set_getkey_callback(ApacheSSLKeyCallback); */
    if(cert_file != NULL)
	{
	if(SSL_use_certificate(con,pConfig->px509Certificate) <= 0)
	    {
	    fprintf(pConfig->fileLogFile,"unable to set certificate\n");
	    ERR_print_errors_fp(pConfig->fileLogFile);
	    SSLLogError(conn->server);
	    return FALSE;
	    }
	if(SSL_use_RSAPrivateKey(con,pConfig->prsaKey) <= 0)
	    {
	    fprintf(pConfig->fileLogFile,"unable to set private key\n");
	    ERR_print_errors_fp(pConfig->fileLogFile);
	    SSLLogError(conn->server);
	    return FALSE;
	    }
	}
    return TRUE;
    }

void ApacheSSLSetupVerify(conn_rec *conn)
    {
    SSLConfigRec *pConfig=get_module_config(conn->server->module_config,&ssl_module);
    int nVerify=VerifyFlags(pConfig);

    conn->client->szClientX509=NULL;

    SSLVerifyConn=conn;

    conn->client->nVerifyError=X509_V_OK;

/* Why call this twice?? Ben */  
#if SSLEAY_VERSION_NUMBER < 0x0800
    SSL_set_verify(conn->client->ssl,nVerify,ApacheSSLVerifyCallback);
#endif
    if(!ApacheSSLSetCertStuff(conn))
	{
	fprintf(pConfig->fileLogFile,"ApacheSSLSetCertStuff failed\n");
	log_error("ApacheSSLSetCertStuff failed",conn->server);
	exit(1);
	}
#if SSLEAY_VERSION_NUMBER >= 0x0800
#else
    SSL_set_verify(conn->client->ssl,nVerify,ApacheSSLVerifyCallback);
#endif
    }

int ApacheSSLSetupConnection(conn_rec * conn)
    {
    server_rec * srvr=conn->server;
    BUFF * fb=conn->client;
    SSLConfigRec *pConfig=get_module_config(srvr->module_config,
					      &ssl_module);
    char *cert_file=pConfig->szCertificateFile;
    char *key_file=pConfig->szKeyFile;

    if(pConfig->bDisabled)
	{
	fb->ssl=NULL;
	return TRUE;
	}
    
    SSLVerifyConn=conn;

    fb->ssl=SSL_new(pConfig->pSSLCtx);
    SSL_set_fd(fb->ssl,fb->fd);

#if 0
    if (cert_file != NULL) {
	if (SSL_use_certificate(fb->ssl,pConfig->px509Certificate) <= 0) {
	    fprintf(pConfig->fileLogFile,"unable to set certificate\n");
	    ERR_print_errors_fp(pConfig->fileLogFile);
	    SSLLogError(srvr);
	    fb->flags |= B_EOF | B_EOUT;
	    return FALSE;
	}

	if(SSL_use_RSAPrivateKey(fb->ssl,pConfig->prsaKey) <= 0) {
	    fprintf(pConfig->fileLogFile,"unable to set private key\n");
	    ERR_print_errors_fp(pConfig->fileLogFile);
	    SSLLogError(srvr);
	    fb->flags |= B_EOF | B_EOUT;
	    return FALSE;
	}

    }
#endif
    ApacheSSLSetupVerify(conn);

    while(!SSL_is_init_finished(fb->ssl))
	{
	int ret=SSL_accept(fb->ssl);
	if (ret <= 0)
	    {
	    log_error("SSL_Accept failed",srvr);
	    SSLLogError(srvr);
	    fb->flags |= B_EOF | B_EOUT;
	    return FALSE;
	    }

	if(conn->client->nVerifyError != X509_V_OK)
	    {
	    log_error("Verification failed",conn->server);
	    SSLLogError(srvr);
	    fb->flags |= B_EOF | B_EOUT;
	    return FALSE;
	    }

	if(pConfig->nVerifyClient == VERIFY_REQUIRE && !conn->client->szClientX509)
	    {
	    log_error("No client certificate",conn->server);
	    SSLLogError(conn->server);
	    return 0;
	    }
	fprintf(pConfig->fileLogFile,"CIPHER is %s\n",SSL_get_cipher(conn->client->ssl));
	fflush(pConfig->fileLogFile);
	}

    /* This should be safe.... so I'll use it */
    SSL_set_read_ahead(fb->ssl,1);

    SSLVerifyConn=NULL;

    return TRUE;
    }

module ssl_module =
    {
    STANDARD_MODULE_STUFF,
    InitSSLServer,		/* initializer */
    CreateSSLDirConfig,		/* dir config creater */
    MergeSSLDirConfig,		/* dir merger --- default is to override */
    CreateSSLServerConfig,	/* server config */
    NULL,			/* merge server config */
    ssl_cmds,			/* command table */
    NULL,			/* handlers */
    NULL,			/* filename translation */
    FakeBasicAuth,		/* check_user_id */
    NULL,			/* check auth */
    SSLCheckCipher,		/* check access */
    NULL,			/* type_checker */
    SSLFixups,			/* fixups */
    NULL,			/* logger */
    };
