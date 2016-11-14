#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <openssl/err.h>

#include <gridsite.h>

int main(int argc, char *argv[])
{
	FILE *fp = NULL;
	int ret = 0;
	int ptrlen, i;
	char *ptr, *tmp, *p;
	char c;
	char *chain = argv[1];
	STACK_OF(X509) *x509_certstack;
	char *vomsdir = "/etc/grid-security/vomsdir";
	char *capath = "/etc/grid-security/certificates";
	GRSTx509Cert *grst_cert = NULL;
	GRSTx509Chain *grst_chain = NULL;

	fp = fopen(chain, "r");
	if (fp == NULL) {
		fprintf(stderr, "Failed to open %s: %s\n", chain, strerror(errno));
		ret = 1;
		goto end;
	}

	ptrlen = 4096;
	ptr = malloc(ptrlen);
	i = 0;
	while ((c = fgetc(fp)) != EOF) {
		ptr[i] = c;
		++i;

		if (i >= ptrlen) {
			ptrlen += 4096;
			tmp = realloc(ptr, ptrlen);
			if (tmp == NULL) {
				fprintf(stderr, "Not enough memory, exiting\n");
				free(ptr);
				ret = 1;
				goto end;
			}
			ptr = tmp;
		}
	}
	fclose(fp);
	fp = NULL;
	ptr[i] = '\0';

	ret = GRSTx509StringToChain(&x509_certstack, ptr);
	free(ptr);
	if (ret != GRST_RET_OK || x509_certstack == NULL) {
		fprintf(stderr, "Failed to parse proxy file for certificate chain\n");
		ret = 1;
		goto end;
	}

	ret = GRSTx509ChainLoadCheck(&grst_chain, x509_certstack, NULL,
                                   capath, vomsdir);
	if ((ret != GRST_RET_OK) ||
		 (grst_chain == NULL) || (grst_chain->firstcert == NULL)) {
			fprintf(stderr, "Failed parsing certificate chain\n");
			ret = 1;
			goto end;
	}

	grst_cert = grst_chain->firstcert;
	for (i=0; grst_cert != NULL; grst_cert = grst_cert->next, ++i) {
		if      (grst_cert->type == GRST_CERT_TYPE_CA)    p = "(CA) ";
		else if (grst_cert->type == GRST_CERT_TYPE_EEC)   p = "(EEC) ";
		else if (grst_cert->type == GRST_CERT_TYPE_PROXY) p = "(PC) ";
		else if (grst_cert->type == GRST_CERT_TYPE_VOMS)  p = "(AC) ";
		else if (grst_cert->type == GRST_CERT_TYPE_ROBOT) p = "(ROBOT) ";
		else p = "";

		printf("%d %s%s\n", i, p,
                  (grst_cert->type == GRST_CERT_TYPE_VOMS)
                    ? grst_cert->value : grst_cert->dn);

		printf(" Status     : %d ( %s%s%s%s%s%s)\n", grst_cert->errors,
                 (grst_cert->errors == 0) ? "OK " : "",
                 (grst_cert->errors & GRST_CERT_BAD_FORMAT) ? "BAD_FORMAT ":"",
                 (grst_cert->errors & GRST_CERT_BAD_CHAIN)  ? "BAD_CHAIN ":"",
                 (grst_cert->errors & GRST_CERT_BAD_SIG)    ? "BAD_SIG ":"",
                 (grst_cert->errors & GRST_CERT_BAD_TIME)   ? "BAD_TIME ":"",
                 (grst_cert->errors & GRST_CERT_BAD_OCSP)   ? "BAD_OCSP ":"");

		printf(" Start      : %s",   ctime(&(grst_cert->notbefore)));
		printf(" Finish     : %s",   ctime(&(grst_cert->notafter)));
		printf(" Delegation : %d\n", grst_cert->delegation);

		if (grst_cert->type == GRST_CERT_TYPE_VOMS) {
			printf(" User DN    : %s\n", grst_cert->dn);
			printf(" VOMS DN    : %s\n\n", grst_cert->issuer);
		} else {
			printf(" Serial     : %s\n", grst_cert->serial);
			printf(" Issuer     : %s\n\n", grst_cert->issuer);
		}
	}
	GRSTx509ChainFree(grst_chain);

	ret = 0;

end:
	if (fp)
		fclose(fp);

	return ret;
}
