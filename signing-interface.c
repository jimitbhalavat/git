#include <sys/types.h>
#include <unistd.h>
#include "cache.h"
#include "config.h"
#include "run-command.h"
#include "strbuf.h"
#include "signing-interface.h"
#include "signing-tool.h"
#include "sigchain.h"
#include "tempfile.h"

extern const struct signing_tool openpgp_tool;
extern const struct signing_tool x509_tool;

static const struct signing_tool *signing_tools[SIGNATURE_TYPE_COUNT] = {
	&openpgp_tool,
	&x509_tool,
};

enum signature_type default_type = SIGNATURE_TYPE_DEFAULT;
static const char* unknown_signature_type = "unknown signature type";
static char* default_signing_key = NULL;

static void add_signature(struct signatures *sigs, struct signature *sig) {
	if (!sigs || !sig)
		return;
	ALLOC_GROW(sigs->sigs, sigs->nsigs + 1, sigs->alloc);
	sigs->sigs[sigs->nsigs++] = sig;
}

void signatures_clear(struct signatures *sigs)
{
	size_t i;
	struct signature *psig;

	if (!sigs) return;
	
	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		strbuf_release(&(psig->sig));
		strbuf_release(&(psig->output));
		strbuf_release(&(psig->status));
		FREE_AND_NULL(psig->signer);
		FREE_AND_NULL(psig->key);
		FREE_AND_NULL(psig->fingerprint);
		FREE_AND_NULL(psig->key);
		FREE_AND_NULL(psig);
	}
	FREE_AND_NULL(sigs->sigs);
	sigs->nsigs = 0;
	sigs->alloc = 0;
}

void signature_clear(struct signature *sigc)
{
	FREE_AND_NULL(sigc->sig.buf);
	FREE_AND_NULL(sigc->output.buf);
	FREE_AND_NULL(sigc->status.buf);
	FREE_AND_NULL(sigc->signer);
	FREE_AND_NULL(sigc->key);
	FREE_AND_NULL(sigc->fingerprint);
	FREE_AND_NULL(sigc->primary_key_fingerprint);
}

int sign_payload(const char *payload, size_t size, struct signatures *sigs,
		enum signature_type st, const char *signing_key)
{
	const struct signing_tool *tool;
	struct signature *psig = xmalloc(sizeof(struct signature));
	int ret;

	fflush(stdout);

	if (!sigs)
		return error("invalid signatures passed to sign function");

	if (!VALID_SIGNATURE_TYPE(st))
		return error("unsupported signature type: %d", st);

	tool = signing_tools[st];

	if (!tool || !tool->sign)
		BUG("signing tool %s undefined", signature_type_name(st));

	ret = tool->sign(payload, size, &psig, signing_key);
	if (!ret)
		add_signature(sigs, psig);
	else

		return error("signing operation failed");

	return 0;
}

int sign_buffer(struct strbuf *buffer, struct strbuf *signature, const char *signing_key)
{
	struct signatures sigs = SIGNATURES_INIT;
	enum signature_type st = default_type;

	int ret = sign_payload(buffer->buf, buffer->len, &sigs, st, signing_key);

	if (!ret)
	{
		strbuf_addstr(signature, sigs.sigs[0]->sig.buf);
	}

	return ret;
}

size_t parse_signatures(const char *payload, size_t size, 
		struct signatures *sigs)
{
	enum signature_type st;
	size_t first;
	size_t begin = 0;
	const struct signing_tool *tool;
	struct signature *psig = NULL;

	first = size;
	for (st = SIGNATURE_TYPE_FIRST; st < SIGNATURE_TYPE_LAST; st++) {
		tool = signing_tools[st];

		if (!tool || !tool->parse)
			BUG("signing tool %s undefined", signature_type_name(st));

		begin = tool->parse(payload, size, &psig);
		if (begin < size) {
			if (sigs)
				add_signature(sigs, psig);
			else
				FREE_AND_NULL(psig);

			first = begin;
			continue;
		}
	}

	return first;
}

size_t parse_signature(const char *buf, size_t size)
{
	size_t match;
	struct signatures sigs = SIGNATURES_INIT;

	if ( !buf || !size )
		return size;

	match = parse_signatures(buf, size, &sigs);

	return match;
}

int verify_buffer_signatures(const char *payload, size_t size,
		struct signatures *sigs)
{
	int ret = 0;
	size_t i;
	const struct signing_tool *tool;
	struct signature *psig;

	if (!sigs)
		error("invalid signatures passed to verify function");

	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		tool = signing_tools[psig->st];

		if (!tool || !tool->verify)
			BUG("signing tool %s undefined", signature_type_name(psig->st));

		ret |= tool->verify(payload, size, psig);
	}

	return ret;
}

int verify_signed_buffer(const char *payload, size_t payload_size,
			 const char *signature, size_t signature_size,
			 struct strbuf *output, struct strbuf *status)
{
	int ret;
	enum signature_type st;
	struct signature sig = SIGNATURE_INIT;
	struct signatures sigs = SIGNATURES_INIT;

	if ( !payload || !signature )
		return error("invalid payload or signature sent !");

	strbuf_addstr(&(sig.sig), signature);
	add_signature(&sigs, &sig);

	ret = verify_buffer_signatures(payload, payload_size, &sigs);

	/*  Some how gpg.format is not sometimes applied, temporary fix to loop and STs */
	if (ret)
	{
		for (st = SIGNATURE_TYPE_FIRST; st < SIGNATURE_TYPE_LAST; st++)
		{
			sig.st = st;
			ret = verify_buffer_signatures(payload, payload_size, &sigs);
			if (!ret || sig.result != '0')
				break;
		}
	}

	if (output)
		strbuf_addstr(output, sig.output.buf);
	if (status)
		strbuf_addstr(status, sig.status.buf);

	return ret;
}

int check_signature(const char *payload, size_t plen, const char *signature,
	size_t slen, struct signature *sigc)
{
	int status;
	enum signature_type st;
	struct signatures sigs = SIGNATURES_INIT;
	struct signature sig = SIGNATURE_INIT;
	
	if (!payload || !signature || !sigc)
		BUG("invalid payload or signature sent !");

	strbuf_addstr(&(sig.sig), signature);
	sig.result = 'N';
	sig.st = default_type;

	add_signature(&sigs, &sig);

	status = verify_buffer_signatures(payload, plen, &sigs);

	/*  Some how gpg.format is not sometimes applied, temporary fix to loop and STs */
	if (status)
	{
		for (st = SIGNATURE_TYPE_FIRST; st < SIGNATURE_TYPE_LAST; st++)
		{
			sig.st = st;
			status = verify_buffer_signatures(payload, plen, &sigs);
			if (!status || sig.result != 'N')
				break;
		}
	}
	status |= sig.result != 'G' && sig.result != 'U';

	if (sig.signer && !sigc->signer)
		sigc->signer = xstrdup(sig.signer);
	if (sig.key && !sigc->key)
		sigc->key = xstrdup(sig.key);
	if (sig.fingerprint && !sigc->fingerprint)
		sigc->fingerprint = xstrdup(sig.fingerprint);
	if (sig.primary_key_fingerprint && !sigc->primary_key_fingerprint)
		sigc->primary_key_fingerprint = xstrdup(sig.primary_key_fingerprint);	

	sigc->st = sig.st;
	sigc->result = sig.result;
	
	strbuf_addstr(&(sigc->sig), payload);
	strbuf_addstr(&(sigc->output), sig.output.buf);
	strbuf_addstr(&(sigc->status), sig.status.buf);

	return !!status;
}

size_t strbuf_append_signatures(struct strbuf *buf, const struct signatures *sigs)
{
	size_t i;
	struct signature *psig;

	if (!buf)
		BUG("invalid buffer passed to signature append function");

	if (!sigs)
		return 0;

	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		strbuf_addbuf(buf, &(psig->sig));
	}

	return sigs->nsigs;
}

void print_signatures(const struct signatures *sigs, unsigned flags)
{
	size_t i;
	const struct signing_tool *tool;
	const struct signature *psig;

	if (!sigs)
		error("invalid signatures passed to verify function");

	for (i = 0; i < sigs->nsigs; i++) {
		psig = sigs->sigs[i];
		tool = signing_tools[psig->st];

		if (!tool || !tool->print)
			BUG("signing tool %s undefined", signature_type_name(psig->st));

		tool->print(psig, flags);
	}
}

void print_signature_buffer(const struct signature *sigc, unsigned flags)
{
	const struct signing_tool *tool;

	if (!sigc)
		error("invalid signatures passed to verify function");

	tool = signing_tools[default_type];

	if (!tool || !tool->print)
		BUG("signing tool %s undefined", signature_type_name(sigc->st));

	tool->print(sigc, flags);
}

enum signature_type signature_type_by_name(const char *name)
{
	enum signature_type st;

	if (!name)
		return default_type;

	for (st = SIGNATURE_TYPE_FIRST; st < SIGNATURE_TYPE_LAST; st++)
		if (!strcmp(signing_tools[st]->name, name))
			return st;

	return error("unknown signature type: %s", name);
}

const char *signature_type_name(enum signature_type st)
{
	if (!VALID_SIGNATURE_TYPE(st))
		return unknown_signature_type;

	return signing_tools[st]->name;
}

int git_signing_config(const char *var, const char *value, void *cb)
{
	int ret = 0;
	char *t1, *t2, *t3, *buf;
	enum signature_type st;
	const struct signing_tool *tool;

	/* user.signingkey is a deprecated alias for signing.<signing.default>.key */
	if (!strcmp(var, "user.signingkey")) {
		if (!value)
			return config_error_nonbool(var);
		
		set_signing_key(value, default_type);

		return 0;
	}

	/* gpg.format is a deprecated alias for signing.default */
	if (!strcmp(var, "gpg.format") || !strcmp(var, "signing.default")) {
		if (!value)
			return config_error_nonbool(var);

		if (!VALID_SIGNATURE_TYPE((st = signature_type_by_name(value))))
			return config_error_nonbool(var);

		set_signature_type(st);

		return 0;
	}

	/* gpg.program is a deprecated alias for signing.openpgp.program */
	if (!strcmp(var, "gpg.program") || !strcmp(var, "signing.openpgp.program")) {
		ret = signing_tools[OPENPGP_SIGNATURE]->config(
				"program", value, cb);

		return ret;
	}

	/* gpg.x509.program is a deprecated alias for signing.x509.program */
	if (!strcmp(var, "gpg.x509.program") || !strcmp(var, "signing.x509.program")) {
		ret = signing_tools[X509_SIGNATURE]->config(
				"program", value, cb);

		return ret;
	}

	buf = xstrdup(var);
	t1 = strtok(buf, ".");
	t2 = strtok(NULL, ".");
	t3 = strtok(NULL, ".");

	/* gpg.<format>.* is a deprecated alias for signing.<format>.* */
	if (!strcmp(t1, "gpg") || !strcmp(t1, "signing")) {
		if (!VALID_SIGNATURE_TYPE((st = signature_type_by_name(t2)))) {
			free(buf);
			return error("unsupported variable: %s", var);
		}

		tool = signing_tools[st];
		if (!tool || !tool->config) {
			free(buf);
			BUG("signing tool %s undefined", signature_type_name(tool->st));
		}

		ret = tool->config(t3, value, cb);
	}

	free(buf);
	return ret;
}

void set_signing_key(const char *key, enum signature_type st)
{
	/*
	 * Make sure we track the latest default signing key so that if the
	 * default signing format changes after this, we can make sure the
	 * default signing tool knows the key to use.
	 */
	free(default_signing_key);
	default_signing_key = xstrdup(key);

	if (!VALID_SIGNATURE_TYPE(st))
		signing_tools[default_type]->set_key(key);
	else
		signing_tools[st]->set_key(key);
}

const char *get_signing_key(enum signature_type st)
{
	if (!VALID_SIGNATURE_TYPE(st))
		return signing_tools[default_type]->get_key();

	return signing_tools[default_type]->get_key();
}

void set_signing_program(const char *signing_program, enum signature_type st)
{
	/*
	 * Make sure we track the latest default signing program so that if the
	 * default signing format changes after this, we can make sure the
	 * default signing tool knows the program to use.
	 */

	if (!VALID_SIGNATURE_TYPE(st))
		signing_tools[default_type]->set_program(signing_program);
	else
		signing_tools[st]->set_program(signing_program);
}

const char *get_signing_program(enum signature_type st)
{
	const char *signing_program = NULL;

	if (!VALID_SIGNATURE_TYPE(st)) {
		signing_program = signing_tools[default_type]->get_program();

		return signing_program;
	}

	signing_program = signing_tools[st]->get_program();

	return signing_program;
}

void set_signature_type(enum signature_type st)
{
	if (!VALID_SIGNATURE_TYPE(st))
		return;

	default_type = st;

	/* 
	 * If the signing key has been set, then make sure the new default
	 * signing tool knows about it. this fixes the order of operations
	 * error of parsing the default signing key and default signing
	 * format in arbitrary order.
	 */
	if (default_signing_key) {
		set_signing_key(default_signing_key, default_type);
	}
}

enum signature_type get_signature_type(void)
{
	return default_type;
}