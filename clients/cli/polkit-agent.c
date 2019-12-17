// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#include "nm-default.h"

#include "polkit-agent.h"

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

#include "nm-polkit-listener.h"
#include "common.h"

#if WITH_POLKIT_AGENT
static char *
nmc_polkit_read_passwd (gpointer instance,
                        const char *action_id,
                        const char *message,
                        const char *user,
                        gpointer user_data)
{
	NmCli *nmc = user_data;

	g_print ("%s\n", message);
	g_print ("(action_id: %s)\n", action_id);

	/* Ask user for polkit authorization password */
	if (user) {
		return nmc_readline_echo (&nmc->nmc_config, FALSE, "password (%s): ", user);
	}
	return nmc_readline_echo (&nmc->nmc_config, FALSE, "password: ");
}

static void
nmc_polkit_registration_error (gpointer instance,
                               const char *error,
                               gpointer user_data)
{
	g_printerr (_("Warning: polkit agent initialization failed: %s\n"), error);
}
#endif

gboolean
nmc_polkit_agent_init (NmCli* nmc, gboolean for_session, GError **error)
{
#if WITH_POLKIT_AGENT
	NMPolkitListener *listener;
	GDBusConnection *dbus_connection = NULL;

	g_return_val_if_fail (error == NULL || *error == NULL, FALSE);

	if (nmc && nmc->client && NM_IS_CLIENT (nmc->client)) {
		dbus_connection = nm_client_get_dbus_connection (nmc->client);
		listener = nm_polkit_listener_new (dbus_connection);
	} else {
		dbus_connection = g_bus_get_sync (G_BUS_TYPE_SYSTEM,
                                          NULL,
                                          error);
		listener = nm_polkit_listener_new (dbus_connection);
		g_object_unref (dbus_connection);
	}

	if (!listener) {
		return FALSE;
	}

	/* connect to signals */
	g_signal_connect (listener,
                      NM_POLKIT_LISTENER_SIGNAL_REQUEST,
                      (GCallback) nmc_polkit_read_passwd,
                      nmc);
	g_signal_connect (listener,
                      NM_POLKIT_LISTENER_SIGNAL_ERROR,
                      (GCallback) nmc_polkit_registration_error,
                      NULL);

	nmc->pk_listener = listener;
#endif
	return TRUE;
}

void
nmc_polkit_agent_fini (NmCli* nmc)
{
#if WITH_POLKIT_AGENT
	if (nmc->pk_listener) {
		g_signal_handlers_disconnect_by_func (nmc->pk_listener,
                                              nmc_polkit_read_passwd,
                                              nmc);
		g_clear_object (&nmc->pk_listener);
	}
#endif
}

gboolean
nmc_start_polkit_agent_start_try (NmCli *nmc)
{
#if WITH_POLKIT_AGENT
	gs_free_error GError *error = NULL;

	/* We don't register polkit agent at all when running non-interactively */
	if (!nmc->ask)
		return TRUE;

	if (!nmc_polkit_agent_init (nmc, FALSE, &error)) {
		g_printerr (_("Warning: polkit agent initialization failed: %s\n"),
                    error->message);
		return FALSE;
	}
#endif
	return TRUE;
}
