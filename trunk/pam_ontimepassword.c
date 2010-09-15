/* los buenos pintores copian, los genios roban - pam_captcha */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/stat.h>

#include <time.h>
#include <sys/uio.h>
#include <fcntl.h>
#include <pwd.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <stdarg.h>
#include <dirent.h>

#include <security/pam_modules.h>
#include <security/pam_appl.h>

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

#define TOTAL_CHALLENGES 24
char *conjunt[]=
{ 
"faiT|e7phei7wao", //00
"aip_ai^chieM7ah", //01
"aht=ah3Puch$ae7", //02
"xae&Ngei4kah9za", //03
"Kohh,aej,aesai4", //04
"utie}xua9Vooyo^", //05
"aih4ohDaiboo$ch", //06
"oobie3choh<T$ie", //07
"ega4ohch$e9jieF", //08
"Ec$eishohe9uuch", //09
"Zies[ai$Pheih7i", //10
"Roh3eethei<vee4", //11
"Ac7yoh4xaey/e$w", //12
"pe!o$rai@chah4Z", //13
"pomaB,ua4Keem3i", //14
"peeJ3ae$b=oQuae", //15
"ahsoo4so?B3ooda", //16
"quaca$ehizie3iB", //17 
"itee:Keb7zeph3u", //18
"phee7Ofo[e9aiPh", //19
"fei7ieToyoo=gh7", //20
"que&gha3She4hai", //21
"zio<y3tieNg,eeb", //22
"Hoh+i9kohtiek7M"  //23
};

static void paminfo(pam_handle_t *pamh, char *fmt, ...);
static void pamvprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, va_list ap);

static void pamprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, ...) {/*{{{*/
  va_list ap;
  va_start(ap, fmt);
  pamvprompt(pamh, style, resp, fmt, ap);
  va_end(ap);
}/*}}}*/

static void pamvprompt(pam_handle_t *pamh, int style, char **resp, char *fmt, va_list ap) {/*{{{*/
  struct pam_conv *conv;
  struct pam_message msg;
  const struct pam_message *msgp;
  struct pam_response *pamresp;
  int pam_err;
  char *text = "";

  vasprintf(&text, fmt, ap);

  pam_get_item(pamh, PAM_CONV, (const void **)&conv);
  pam_set_item(pamh, PAM_AUTHTOK, NULL);

  msg.msg_style = style;;
  msg.msg = text;
  msgp = &msg;
  pamresp = NULL;
  pam_err = (*conv->conv)(1, &msgp, &pamresp, conv->appdata_ptr);

  if (pamresp != NULL) {
    if (resp != NULL)
      *resp = pamresp->resp;
    else
      free(pamresp->resp);
    free(pamresp);
  }

  free(text);
}/*}}}*/

static void paminfo(pam_handle_t *pamh, char *fmt, ...) {
  va_list ap;
  va_start(ap, fmt);
  pamvprompt(pamh, PAM_TEXT_INFO, NULL, fmt, ap);
  va_end(ap);
}

PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
  int idx;
  char *resp;
  int ret=PAM_PERM_DENIED;
  char *user, *host;
	//temps
	time_t rawtime;
	struct tm * timeinfo;
	char hora[3];

  pam_get_item(pamh, PAM_USER, (const void **)&user);
  pam_get_item(pamh, PAM_RHOST, (const void **)&host);

  srand(time(NULL)); /* XXX: Should we seed by something less predictable? */

  /* XXX: Uncomment this to have the screen cleared before proceeding */
  //paminfo(pamh, "[2J[0;0H");

  //si es el user de OTP:

  paminfo(pamh, " Necesitaras algo mes que un password de res per entrar aqui");
  paminfo(pamh, "-------------------------------------------------------------\n");

  openlog("pam_ontimepassword", 0, LOG_AUTHPRIV);

	//aixi no te en compte la zona horaria	
	//idx=(time(NULL)%(3600*24))/3600;
	
	time (&rawtime);	
	timeinfo = localtime(&rawtime);
	strftime(hora,3,"%H",timeinfo);
	idx=atoi(hora);

	
	//fer coses	
  pamprompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "\ndisme alguna cosa divertida: ");

  if (strcmp(resp, conjunt[idx]) == 0)
		ret=PAM_SUCCESS;

  if (ret != PAM_SUCCESS) 
	{
    syslog(LOG_INFO, "User %s failed to pass the on time password (from %s) - %s: %s", user, host, hora, conjunt[idx]);
    sleep(3); /* Irritation! */
  }
	else 
    syslog(LOG_INFO, "User %s passed the on time password (from %s) - %s: %s", user, host, hora, conjunt[idx]);

	//temporal
	//ret=PAM_SUCCESS;

  closelog();
	free(resp);
  return ret;
}

PAM_EXTERN int
pam_sm_setcred(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

  return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_acct_mgmt(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SUCCESS);
}

PAM_EXTERN int
pam_sm_chauthtok(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{

    return (PAM_SERVICE_ERR);
}

#ifdef PAM_MODULE_ENTRY
PAM_MODULE_ENTRY("pam_ontimepassword");
#endif
