// SPDX-License-Identifier: GPL-2.0+
/*
 * Copyright (C) 2014 Red Hat, Inc.
 */

#ifndef __NM_POLKIT_LISTENER_H__
#define __NM_POLKIT_LISTENER_H__

#include "nm-default.h"

#if WITH_POLKIT_AGENT

#define NM_TYPE_POLKIT_LISTENER            (nm_polkit_listener_get_type ())
G_DECLARE_FINAL_TYPE (NMPolkitListener, nm_polkit_listener, NM, POLKIT_LISTENER, GObject)

NMPolkitListener *nm_polkit_listener_new (GDBusConnection *dbus_connection);

/* Signals */
#define NM_POLKIT_LISTENER_SIGNAL_REQUEST "secret-request"
#define NM_POLKIT_LISTENER_SIGNAL_ERROR   "registration-error"

#endif

#endif /* __NM_POLKIT_LISTENER_H__ */
