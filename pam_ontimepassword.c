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

#include "md5.h"

#ifndef PAM_EXTERN
#define PAM_EXTERN
#endif

//#define _LOG_HASH_

//pels sosos
//#define _FORTUNE_JORDI_

#ifdef _FORTUNE_JORDI_

#define COUNT_FORTUNE 30
char *fortune[]=
{
	"A veces veo errores",
	"El kernel s'ha espantat",
	"Vigila amb l'ornitorring, si t'atrapa et convertira en un objecte",
	"li treus tota la serietat al projecte",
	"solo veo una pantalla con printf's en ella.",
	"Sois programadores hard",
	"HARi was HERE",
	"I want to believe",
	"a q te meto un troyano q ja veras",
	"fes-ho o no ho fagis, pero no ho intentis -- El mestre ioda",
	"Envieu-nos diners o ens morirem de gana",
	"el conocimiento humano petenece al mundo",
	"no lo entiendes steven? eso NO importa",
	"el bien de la mayoria es superior al bien de la minoria i al de uno solo -- Spock",
	"fem que la historia no oblidi mai el nom de enterprise",
	"los buenos pintores copian, los genios roban",
	"jo no nomes reinventare la roda, sino que quan acabi la patentare",
	"com tots sabeu java es un invent de hp",
	"nomes es per provocar",
	"tal com Microsoft diu: la culpa es del hardware",
	"vull tancar el #operacion_trueno i vull fer un bat que quan s'executi una imatge robi el passwords. pq un troyano ja se aniria a 1 mega i no colaria",
	"es que aixo del c es un llenguatge lent, En java es un lleguatge rapid -- MagBox",
	"A pero a la maquina senzilla no es poden fer MUL? -- Logann",
	"Com vols que els caixes automatics estiguin connectats a la xarxa -- R00TD0WN",
	"esq amb l'imici ja em surt una finestra qui la hobre encare q no escrigui res",
	"Avui he canivat el logo de windows, soc un Hacker -- TvKeeper",
	"talk root@alei.upf.es -- Xev",
	"M'ha arribat el teu text amb una colla de caracters inutils. Cal que m'enviis el text en format Word.",
	"moriras Freezer!",
	"no es el mateix un client blanc que un client negre"
};

#endif

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

/* Computes the message digest for string inString.
 * Prints out message digest, a space, the string (in quotes) and a
 * carriage return.
 */

char* MD5string (char *inString)
{
	char *md5=NULL;
	MD5_CTX mdContext;
	unsigned int len = strlen (inString);
	int i=0;

	MD5Init (&mdContext);
	MD5Update (&mdContext, inString, len);
	MD5Final (&mdContext);
	
	md5=malloc(1+(sizeof(char)*2*16));

  for (i = 0; i < 16; i++)
    snprintf (md5+(i*2), 3, "%02x", mdContext.digest[i]);
	
	//*(md5+16*2+1)=0;

	return md5;	
}


PAM_EXTERN int
pam_sm_authenticate(pam_handle_t *pamh, int flags,
    int argc, const char *argv[])
{
  int idx;
#ifdef _FORTUNE_JORDI_
	int fortune_i;
#endif
  char *resp;
  int ret=PAM_PERM_DENIED;
  char *user, *host;
	//temps
	time_t rawtime;
	struct tm * timeinfo;
	char hora[3];
	char *password;
	int ssalt=0;

  pam_get_item(pamh, PAM_USER, (const void **)&user);
  pam_get_item(pamh, PAM_RHOST, (const void **)&host);

  srand(time(NULL)); /* XXX: Should we seed by something less predictable? */

  /* XXX: Uncomment this to have the screen cleared before proceeding */
  //paminfo(pamh, "[2J[0;0H");

  //si es el user de OTP:

#ifdef _FORTUNE_JORDI_

  paminfo(pamh, " Necesitaras algo mes que un password de res per entrar aqui");
  paminfo(pamh, "-------------------------------------------------------------\n");

#endif

  openlog("pam_ontimepassword", 0, LOG_AUTHPRIV);

	//aixi no te en compte la zona horaria	
	//idx=(time(NULL)%(3600*24))/3600;
	
	time (&rawtime);	
	timeinfo = localtime(&rawtime);
	strftime(hora,3,"%H",timeinfo);
	idx=atoi(hora);

	if(argc >= 1)
	{
		ssalt=strlen(argv[0]);
		password=malloc((sizeof(char)*ssalt)+1+1+2); //tamany salt + 1 per l'espai + 1 per el \0 + 2 per la hora
		snprintf(password,(sizeof(char)*ssalt)+1+1+2,"%s %s",argv[0],hora);
	}
	else
	{
		password=malloc(18*sizeof(char)); // $ echo "systemadmin.es 10" | wc -c; 18
		snprintf(password,18*sizeof(char),"systemadmin.es %s",hora);
	}
		
	char *md5=MD5string(password);

	//fer coses	

	#ifdef _FORTUNE_JORDI_	

		fortune_i = rand() % COUNT_FORTUNE;
		pamprompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "\n%s - %s: ", md5, fortune[fortune_i]);

	#else

		pamprompt(pamh, PAM_PROMPT_ECHO_OFF, &resp, "what time is it?: ");
	
	#endif

  if (strcmp(resp, md5) == 0)
		ret=PAM_SUCCESS;

  if (ret != PAM_SUCCESS) 
	{
	
		#ifdef _LOG_HASH_
			syslog(LOG_INFO, "User %s failed to pass the on time password (from %s) - %s: %s", user, host, password, md5);
		#else
			syslog(LOG_INFO, "User %s failed to pass the on time password (from %s)",user, host);
		#endif
		
   	//#warning sense sleep!!!
   	sleep(3); /* Irritation! */
		
		paminfo(pamh,"There must be some kind of way out of here\n");
  }
	else 
	{
		#ifdef _LOG_HASH_
			syslog(LOG_INFO, "User %s passed the on time password (from %s) - %s: %s", user, host, password, md5);
		#else
			syslog(LOG_INFO, "User %s passed the on time password (from %s)", user, host);
		#endif

		paminfo(pamh,"Said the joker to the thief\n");
	}

	//temporal
	//ret=PAM_SUCCESS;
	
	//allibero el md5 i password al acabar
	free(md5); free(password);

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
