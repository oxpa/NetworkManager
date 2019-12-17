// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

/**
 * SECTION:nm-polkit-listener
 * @short_description: A polkit agent listener
 *
 * #NMPolkitListener is the polkit agent listener used by nmcli and nmtui.
 * http://www.freedesktop.org/software/polkit/docs/latest/index.html
 *
 * For an example polkit agent you can look at polkit source tree:
 * http://cgit.freedesktop.org/polkit/tree/src/polkitagent/polkitagenttextlistener.c
 * http://cgit.freedesktop.org/polkit/tree/src/programs/pkttyagent.c
 * or LXDE polkit agent:
 * http://git.lxde.org/gitweb/?p=debian/lxpolkit.git;a=blob;f=src/lxpolkit-listener.c
 * https://github.com/lxde/lxqt-policykit/tree/master/src
 */

#include "nm-polkit-listener.h"

#include <gio/gio.h>
#include <gio/gunixoutputstream.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <pwd.h>

#include "nm-glib-aux/nm-dbus-aux.h"
#include "nm-libnm-core-intern/nm-auth-subject.h"
#include "c-list/src/c-list.h"

#if WITH_POLKIT_AGENT

#define POLKIT_BUS_NAME             "org.freedesktop.PolicyKit1"

#define POLKIT_AUTHORITY_OBJ_PATH   "/org/freedesktop/PolicyKit1/Authority"
#define POLKIT_AUTHORITY_IFACE_NAME "org.freedesktop.PolicyKit1.Authority"

#define POLKIT_AGENT_OBJ_PATH       "/org/freedesktop/PolicyKit1/AuthenticationAgent"
#define POLKIT_AGENT_DBUS_INTERFACE "org.freedesktop.PolicyKit1.AuthenticationAgent"

#define NM_POLKIT_LISTENER_DBUS_CONNECTION "dbus-connection"

#ifndef POLKIT_PACKAGE_PREFIX
#define POLKIT_PACKAGE_PREFIX "/usr"
#endif

/*****************************************************************************/

enum {
	REQUEST,
	ERROR,
	LAST_SIGNAL
};

static guint signals[LAST_SIGNAL] = { 0 };

struct _NMPolkitListener {
	GObject parent;

	GDBusConnection *dbus_connection;
	char *pk_bus_name;
	guint pk_auth_agent_reg_id;
	guint pk_bus_name_changed_id;
	GCancellable *cancellable;
	GMainContext *main_context;
	CList request_lst_head;
};

G_DEFINE_TYPE (NMPolkitListener, nm_polkit_listener, G_TYPE_OBJECT)

/*****************************************************************************/

typedef struct {
	CList link;

	NMPolkitListener *listener;
	char *action_id;
	char *message;
	char *username;
	char *cookie;

	pid_t child_pid;
	int child_stdout;
	GOutputStream *child_stdin_stream;
	GIOChannel *child_stdout_channel;
	GSource *child_stdout_watch_source;
	gboolean helper_is_running;
	GCancellable *auth_cancellable;
	GDBusMethodInvocation *dbus_invocation;
} AuthRequest;

static const GDBusInterfaceInfo interface_info = NM_DEFINE_GDBUS_INTERFACE_INFO_INIT (
	POLKIT_AGENT_DBUS_INTERFACE,
	.methods = NM_DEFINE_GDBUS_METHOD_INFOS (
		NM_DEFINE_GDBUS_METHOD_INFO (
			"BeginAuthentication",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("action_id", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("message", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("icon_name", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("details", "a{ss}"),
				NM_DEFINE_GDBUS_ARG_INFO ("cookie", "s"),
				NM_DEFINE_GDBUS_ARG_INFO ("identities", "a(sa{sv})"),
			),
		),
        NM_DEFINE_GDBUS_METHOD_INFO (
			"CancelAuthentication",
			.in_args = NM_DEFINE_GDBUS_ARG_INFOS (
				NM_DEFINE_GDBUS_ARG_INFO ("cookie", "s"),
			),
		),
	),
);

static void
remove_request (AuthRequest *request)
{
	int status;

	nm_clear_g_cancellable (&request->auth_cancellable);

	/* kill and wait afterwards */
	if (request->child_pid > 0) {
		kill (request->child_pid, SIGTERM);
	}

	nm_clear_g_free (&request->action_id);
	nm_clear_g_free (&request->message);
	nm_clear_g_free (&request->username);
	nm_clear_g_free (&request->cookie);

	if (request->child_stdout_watch_source) {
		g_source_destroy (request->child_stdout_watch_source);
		g_source_unref (request->child_stdout_watch_source);
		request->child_stdout_watch_source = NULL;
	}

	if (request->child_stdout_channel) {
		g_io_channel_unref (request->child_stdout_channel);
		request->child_stdout_channel = NULL;
	}

	if (request->child_stdout != -1) {
		request->child_stdout = -1;
	}

	/* wait for child termination */
	if (request->child_pid > 0) {
		kill (request->child_pid, SIGTERM);
		waitpid (request->child_pid, &status, 0);
		request->child_pid = 0;
	}

	g_clear_object (&request->child_stdin_stream);
	request->helper_is_running = FALSE;

	c_list_unlink (&request->link);
}

static const char *
uid_to_name (uid_t uid)
{
	const char *name = NULL;
	struct passwd *passwd;

	passwd = getpwuid (uid);
	if (passwd != NULL)
		name = passwd->pw_name;
	return name;
}

static gboolean
find_identity (uid_t uid, gpointer user_data)
{
	return nm_streq0 ((const char *)user_data,
                      uid_to_name(uid));
}

static gboolean
first_identity (uid_t uid, gpointer user_data)
{
	return true;
}

static gint64
_choose_identity (GVariant *identities,
                  gboolean (*predicate)(uid_t uid, gpointer user_data),
                  gpointer user_data)
{
	GVariantIter identity_iter;
	GVariantIter *identity_details_iter;
	GVariant *unix_id_variant;
	uid_t unix_id;

	g_return_val_if_fail (predicate != NULL, FALSE);

	g_variant_iter_init (&identity_iter, identities);

	while (g_variant_iter_loop (&identity_iter, "(&sa{sv})", NULL, &identity_details_iter)) {
		while (g_variant_iter_loop (identity_details_iter, "{sv}", NULL, &unix_id_variant)) {
			unix_id = g_variant_get_uint32 (unix_id_variant);

			if (predicate (unix_id, user_data)) {
				g_variant_unref (unix_id_variant);
				g_variant_iter_free (identity_details_iter);
				return unix_id;
			}
		}
		g_variant_iter_free (identity_details_iter);
	}
	return -1;
}

static uid_t
choose_identity (GVariant *identities)
{
	const char *user;
	gint64 id;

	/* Choose identity. First try current user, then root, and else
	 * take the first one */
	user = getenv("USER");

	if ((id = _choose_identity (identities, find_identity, (gpointer) user)) >= 0) {
		return id;
	} else if ((id = _choose_identity (identities, find_identity, "root")) >= 0) {
		return id;
	}

	return _choose_identity (identities, first_identity, NULL);
}

static void
agent_register_cb (GObject *source_object,
                   GAsyncResult *res,
                   gpointer user_data)
{
	gs_free_error GError *error = NULL;
	GVariant *ret = NULL;
	NMPolkitListener *listener = NM_POLKIT_LISTENER (user_data);
	GDBusConnection *dbus_connection = G_DBUS_CONNECTION (source_object);

	ret = g_dbus_connection_call_finish (dbus_connection,
                                         res,
                                         &error);
	if (!res) {
		g_signal_emit (listener,
                       signals[ERROR],
                       0,
                       error->message);
		return;
	}
	g_variant_unref (ret);
}

static void
agent_register (NMPolkitListener *self)
{
	const char *locale = NULL;
	NMAuthSubject *subject = NULL;
	GVariant *subject_variant = NULL;

	locale = g_getenv ("LANG");
	if (locale == NULL)
		locale = "en_US.UTF-8";

	subject = nm_auth_subject_new_unix_process_self ();
	subject_variant = nm_auth_subject_unix_process_to_polkit_gvariant(subject);

	g_dbus_connection_call (self->dbus_connection,
                            self->pk_bus_name,
                            POLKIT_AUTHORITY_OBJ_PATH,
                            POLKIT_AUTHORITY_IFACE_NAME,
                            "RegisterAuthenticationAgent",
                            g_variant_new ("(@(sa{sv})ss)",
                                           subject_variant,
                                           locale,
                                           POLKIT_AGENT_OBJ_PATH),
                            NULL,
                            G_DBUS_CALL_FLAGS_NONE,
                            -1,
                            self->cancellable,
                            agent_register_cb,
                            self);
	g_object_unref (subject);
}

static void
agent_unregister (NMPolkitListener *self)
{
	NMAuthSubject *subject = NULL;
	GVariant *subject_variant = NULL;

	subject = nm_auth_subject_new_unix_process_self ();
	subject_variant = nm_auth_subject_unix_process_to_polkit_gvariant(subject);

	g_dbus_connection_call (self->dbus_connection,
                            self->pk_bus_name,
                            POLKIT_AUTHORITY_OBJ_PATH,
                            POLKIT_AUTHORITY_IFACE_NAME,
                            "UnregisterAuthenticationAgent",
                            g_variant_new ("(@(sa{sv})s)",
                                           subject_variant,
                                           POLKIT_AGENT_OBJ_PATH),
                            NULL,
                            G_DBUS_CALL_FLAGS_NONE,
                            -1,
                            NULL,
                            NULL,
                            self);
	g_object_unref (subject);
}

static void
write_response_to_helper (AuthRequest *request, const char *response)
{
	gboolean add_newline;
	const char line_terminator[] = "\n";
	gsize response_len;

	g_return_if_fail (response);

	response_len = strlen (response);
	add_newline = (response[response_len] != '\n');

	g_output_stream_write_all (request->child_stdin_stream,
                               response,
                               response_len,
                               NULL,
                               request->auth_cancellable,
                               NULL);

	if (add_newline) {
		g_output_stream_write_all (request->child_stdin_stream,
                                   line_terminator,
                                   1,
                                   NULL,
                                   request->auth_cancellable,
                                   NULL);
	}
}

static void
complete_authentication (AuthRequest *request,
                         gboolean result)
{
	if (result) {
		g_dbus_method_invocation_return_value(request->dbus_invocation, NULL);
	} else {
		g_dbus_method_invocation_return_dbus_error(request->dbus_invocation,
                                                   "org.freedesktop.PolicyKit1.Error.Failed",
                                                   "");
	}
	remove_request (request);
}

static gboolean
io_watch_have_data (GIOChannel    *channel,
                    GIOCondition   condition,
                    gpointer       user_data)
{
	AuthRequest *request = user_data;
	gs_free char *line = NULL;
	gs_free char *unescaped = NULL;
	gs_free char *response = NULL;
	gboolean ret = FALSE;

	if (!request->helper_is_running) {
		complete_authentication (request, FALSE);
		goto out;
	}

	g_io_channel_read_line (channel,
                            &line,
                            NULL,
                            NULL,
                            NULL);
	if (!line) {
		/* In case we get just G_IO_HUP, line is NULL*/
		g_signal_emit (request->listener,
                       signals[ERROR],
                       0,
                       "Error reading line from PolicyKit setuid helper");
		complete_authentication (request, FALSE);
		goto out;
	}

	/* remove terminator */
	if (strlen (line) > 0 && line[strlen (line) - 1] == '\n')
		line[strlen (line) - 1] = '\0';

	unescaped = g_strcompress (line);

	if (g_str_has_prefix (unescaped, "PAM_PROMPT_ECHO")) {
		/* emit signal and wait for response */
		g_signal_emit (request->listener,
                       signals[REQUEST],
                       0,
                       request->action_id,
                       request->message,
                       request->username,
                       &response);

		if (response) {
			write_response_to_helper (request, response);
		} else {
			complete_authentication (request, FALSE);
		}
		ret = TRUE;
	} else if (g_str_has_prefix (unescaped, "SUCCESS")) {
		complete_authentication (request, TRUE);
	} else if (g_str_has_prefix (unescaped, "FAILURE")) {
		complete_authentication (request, FALSE);
	} else {
		complete_authentication (request, FALSE);
	}

out:
	if (condition & (G_IO_ERR | G_IO_HUP)) {
		complete_authentication (request, FALSE);
	}
	return ret;
}

static void
begin_authentication (AuthRequest *request)
{
	char *helper_argv[3];
	int stdin_fd = -1;

	helper_argv[0] = POLKIT_PACKAGE_PREFIX "/lib/polkit-1/polkit-agent-helper-1";
	helper_argv[1] = request->username;
	helper_argv[2] = NULL;

	if (!g_spawn_async_with_pipes (NULL,
                                   (char **) helper_argv,
                                   NULL,
                                   G_SPAWN_DO_NOT_REAP_CHILD |
                                   0,//G_SPAWN_STDERR_TO_DEV_NULL,
                                   NULL,
                                   NULL,
                                   &request->child_pid,
                                   &stdin_fd,
                                   &request->child_stdout,
                                   NULL,
                                   NULL)) {
		complete_authentication (request, FALSE);
		return;
	}

	request->child_stdin_stream = g_unix_output_stream_new (stdin_fd, TRUE);

	/* Write the cookie on stdin so it can't be seen by other processes */
	if (!g_output_stream_write_all (request->child_stdin_stream,
                                    request->cookie,
                                    strlen (request->cookie),
                                    NULL,
                                    request->auth_cancellable,
                                    NULL) ||
		!g_output_stream_write_all (request->child_stdin_stream,
                                    "\n",
                                    1,
                                    NULL,
                                    request->auth_cancellable,
                                    NULL)) {
		complete_authentication (request, FALSE);
		return;
	}

	request->child_stdout_channel = g_io_channel_unix_new (request->child_stdout);
	request->child_stdout_watch_source = g_io_create_watch (request->child_stdout_channel,
                                                         G_IO_IN | G_IO_ERR | G_IO_HUP);
	g_source_set_callback (request->child_stdout_watch_source,
                           G_SOURCE_FUNC (io_watch_have_data),
                           request,
                           NULL);
	g_source_attach (request->child_stdout_watch_source,
                     request->listener->main_context);

	request->helper_is_running = TRUE;
	return;
}

static AuthRequest*
get_request (NMPolkitListener *listener,
                    const char *cookie)
{
	AuthRequest *request;

	if (!c_list_is_empty (&listener->request_lst_head)) {
		c_list_for_each_entry (request, &listener->request_lst_head, link) {
			if (nm_streq0 (cookie, request->cookie)) {
				return request;
			}
		}
	}
	return NULL;
}

static AuthRequest*
create_request (NMPolkitListener *listener,
                GDBusMethodInvocation *invocation,
                const char *action_id,
                const char *message,
                const char *username,
                const char *cookie)
{
	AuthRequest *request = g_slice_new0(AuthRequest);

	request->listener = listener;
	request->dbus_invocation = invocation;
	request->auth_cancellable = g_cancellable_new ();
	request->action_id = g_strdup (action_id);
	request->message = g_strdup (message);
	request->username = g_strdup (username);
	request->cookie = g_strdup (cookie);
	request->helper_is_running = FALSE;

	c_list_link_tail (&listener->request_lst_head, &request->link);
	return request;
}

static void
dbus_method_call_cb (GDBusConnection *connection,
                     const char *sender,
                     const char *object_path,
                     const char *interface_name,
                     const char *method_name,
                     GVariant *parameters,
                     GDBusMethodInvocation *invocation,
                     gpointer user_data)
{
	NMPolkitListener *listener = user_data;
	const char *action_id;
	const char *message;
	const char *cookie;
	AuthRequest *request;
	gs_unref_variant GVariant *identities_gvariant;
	uid_t uid;

	if (nm_streq0 (method_name, "BeginAuthentication")) {
		g_variant_get (parameters,
                       "(&s&s&s@a{ss}&s@a(sa{sv}))",
                       &action_id,
                       &message,
                       NULL,
                       NULL,
                       &cookie,
                       &identities_gvariant);

		uid = choose_identity(identities_gvariant);

		request = create_request (listener,
                                  invocation,
                                  action_id,
                                  message,
                                  uid_to_name (uid),
                                  cookie);
		begin_authentication(request);
	} else if (nm_streq0 (method_name, "CancelAuthentication")) {
		g_variant_get (parameters,
                       "&s",
                       &cookie);
		request = get_request (listener, cookie);

		if (request) {
			complete_authentication (request, FALSE);
		}
	}
}

static gboolean
export_dbus_iface (NMPolkitListener *self, GError **error)
{
	GDBusInterfaceVTable interface_vtable = {
		.method_call = dbus_method_call_cb,
		.set_property = NULL,
		.get_property = NULL,
	};

	g_return_val_if_fail (NM_IS_POLKIT_LISTENER (self), FALSE);
	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	/* Agent listener iface has been exported already */
	if (self->pk_auth_agent_reg_id) {
		return TRUE;
	}

	self->pk_auth_agent_reg_id =
		g_dbus_connection_register_object (self->dbus_connection,
                                           POLKIT_AGENT_OBJ_PATH,
                                           (GDBusInterfaceInfo*) &interface_info,
                                           &interface_vtable,
                                           self,
                                           NULL,
                                           error);
	if (!self->pk_auth_agent_reg_id) {
		g_signal_emit (self,
                       signals[ERROR],
                       0,
                       "Could not register as a PolicyKit Authentication Agent");
	}
	return self->pk_auth_agent_reg_id;
}

static void
pk_bus_name_changed (NMPolkitListener *self,
                     const char *name_owner)
{
	gs_free_error GError *error = NULL;

	name_owner = nm_str_not_empty (name_owner);

	if (nm_streq0 (self->pk_bus_name, name_owner)) {
		return;
	}

	g_free (self->pk_bus_name);
	self->pk_bus_name = g_strdup (name_owner);

	if (!self->pk_bus_name) {
		return;
	}

	if (export_dbus_iface (self, &error)) {
		agent_register (self);
	}
}

static void
pk_bus_name_changed_cb (GDBusConnection *connection,
                        const char *sender_name,
                        const char *object_path,
                        const char *interface_name,
                        const char *signal_name,
                        GVariant *parameters,
                        gpointer user_data)
{
	NMPolkitListener *self = user_data;
	const char *new_owner;

	if (!g_variant_is_of_type (parameters, G_VARIANT_TYPE ("(sss)"))) {
		return;
	}

	g_variant_get (parameters,
                   "(&s&s&s)",
                   NULL,
                   NULL,
                   &new_owner);

	pk_bus_name_changed (self, new_owner);
}

static void
get_name_owner_cb (const char *name_owner,
                   GError *error,
                   gpointer user_data)
{
	if (!name_owner && g_error_matches (error, G_IO_ERROR, G_IO_ERROR_CANCELLED)) {
		return;
	}
	pk_bus_name_changed (user_data, name_owner);
}

/*****************************************************************************/

NM_GOBJECT_PROPERTIES_DEFINE (NMPolkitListener,
	PROP_DBUS_CONNECTION,
);

static void
nm_polkit_listener_set_property (GObject *object, guint prop_id,
              const GValue *value, GParamSpec *pspec)
{
	NMPolkitListener *self = NM_POLKIT_LISTENER (object);

	switch (prop_id) {
	case PROP_DBUS_CONNECTION:
		self->dbus_connection = g_value_dup_object (value);
		break;
	default:
		G_OBJECT_WARN_INVALID_PROPERTY_ID (object, prop_id, pspec);
		break;
	}
}

static void
nm_polkit_listener_init (NMPolkitListener *self)
{
	c_list_init (&self->request_lst_head);
	self->main_context = g_main_context_ref_thread_default();
}

static void
nm_polkit_listener_constructed (GObject *object)
{
	NMPolkitListener *self = NM_POLKIT_LISTENER (object);

	self->cancellable = g_cancellable_new();

	self->pk_bus_name_changed_id =
        nm_dbus_connection_signal_subscribe_name_owner_changed (self->dbus_connection,
                                                                POLKIT_BUS_NAME,
                                                                pk_bus_name_changed_cb,
                                                                self,
                                                                NULL);

	nm_dbus_connection_call_get_name_owner (self->dbus_connection,
                                            POLKIT_BUS_NAME,
                                            -1,
                                            self->cancellable,
                                            get_name_owner_cb,
                                            self);

	G_OBJECT_CLASS (nm_polkit_listener_parent_class)->constructed (object);
}

static void
nm_polkit_listener_dispose (GObject *object)
{
	NMPolkitListener *self = NM_POLKIT_LISTENER (object);
	AuthRequest *request, *request_safe;

	nm_clear_g_cancellable(&self->cancellable);

	if (!c_list_is_empty (&self->request_lst_head)) {
		c_list_for_each_entry_safe_unlink (request,
                                           request_safe,
                                           &self->request_lst_head,
                                           link) {
			remove_request (request);
		}
	}

	if (self->dbus_connection) {
		nm_clear_g_dbus_connection_signal (self->dbus_connection,
                                           &self->pk_bus_name_changed_id);
		g_dbus_connection_unregister_object (self->dbus_connection,
                                             self->pk_auth_agent_reg_id);
		agent_unregister (self);
		nm_clear_g_free (&self->pk_bus_name);
		g_clear_object (&self->dbus_connection);
	}

	if (self->main_context) {
		g_main_context_unref (self->main_context);
		self->main_context = NULL;
	}

	G_OBJECT_CLASS (nm_polkit_listener_parent_class)->dispose (object);
}

/**
 * nm_polkit_listener_new:
 * @dbus_connection: a open DBus connection
 *
 * Creates a new #NMPolkitListener and registers it as a polkit agent.
 *
 * Returns: a new #NMPolkitListener
 */
NMPolkitListener *
nm_polkit_listener_new (GDBusConnection *dbus_connection)
{
	return g_object_new(NM_TYPE_POLKIT_LISTENER,
                        NM_POLKIT_LISTENER_DBUS_CONNECTION, dbus_connection,
                        NULL);
}

static void
nm_polkit_listener_class_init (NMPolkitListenerClass *klass)
{
	GObjectClass *object_class = G_OBJECT_CLASS (klass);

	object_class->set_property = nm_polkit_listener_set_property;
	object_class->constructed = nm_polkit_listener_constructed;
	object_class->dispose = nm_polkit_listener_dispose;

	obj_properties[PROP_DBUS_CONNECTION] =
		g_param_spec_object (NM_POLKIT_LISTENER_DBUS_CONNECTION, "", "",
                             G_TYPE_DBUS_CONNECTION,
                             G_PARAM_CONSTRUCT_ONLY |
                             G_PARAM_WRITABLE |
                             G_PARAM_STATIC_STRINGS);

	g_object_class_install_properties (object_class,
                                       _PROPERTY_ENUMS_LAST,
                                       obj_properties);

	signals[REQUEST] =
		g_signal_new (NM_POLKIT_LISTENER_SIGNAL_REQUEST,
                      NM_TYPE_POLKIT_LISTENER,
                      G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE,
                      0,
                      NULL,
                      NULL,
                      NULL,
                      G_TYPE_STRING,
                      3,
                      G_TYPE_STRING,
                      G_TYPE_STRING,
                      G_TYPE_STRING);
	signals[ERROR] =
		g_signal_new (NM_POLKIT_LISTENER_SIGNAL_ERROR,
                      NM_TYPE_POLKIT_LISTENER,
                      G_SIGNAL_RUN_LAST | G_SIGNAL_NO_RECURSE,
                      0,
                      NULL,
                      NULL,
                      NULL,
                      G_TYPE_NONE,
                      1,
                      G_TYPE_STRING);
}

#endif /* WITH_POLKIT_AGENT */
