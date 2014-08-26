/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*- */
/*
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, write to the
 * Free Software Foundation, Inc., 51 Franklin Street, Fifth Floor,
 * Boston, MA 02110-1301 USA.
 *
 * Copyright 2008 Red Hat, Inc.
 */

#include <glib.h>
#include <dbus/dbus-glib.h>
#include <string.h>
#include "nm-types.h"
#include "nm-types-private.h"
#include "nm-object-private.h"
#include "nm-object-cache.h"
#include "nm-dbus-glib-types.h"
#include "nm-setting-ip6-config.h"

static gpointer
_nm_uint_array_copy (GArray *src)
{
	GArray *dest;

	dest = g_array_sized_new (FALSE, TRUE, sizeof (guint32), src->len);
	g_array_append_vals (dest, src->data, src->len);
	return dest;
}

static void
_nm_uint_array_free (GArray *array)
{
	g_array_free (array, TRUE);
}

GType
nm_uint_array_get_type (void)
{
	static GType our_type = 0;

	if (our_type == 0)
		our_type = g_boxed_type_register_static (g_intern_static_string ("NMUintArray"),
		                                         (GBoxedCopyFunc) _nm_uint_array_copy,
		                                         (GBoxedFreeFunc) _nm_uint_array_free);
	return our_type;
}

gboolean
_nm_uint_array_demarshal (GValue *value, GArray **dest)
{
	GArray *array;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_UINT_ARRAY))
		return FALSE;

	if (*dest) {
		g_boxed_free (NM_TYPE_UINT_ARRAY, *dest);
		*dest = NULL;
	}

	array = (GArray *) g_value_get_boxed (value);
	if (array && (array->len > 0)) {
		*dest = g_array_sized_new (FALSE, TRUE, sizeof (guint32), array->len);
		g_array_append_vals (*dest, array->data, array->len);
	}

	return TRUE;
}

/*****************************/

static gpointer
_nm_ip6_address_object_array_copy (GPtrArray *src)
{
	GPtrArray *dest;
	int i;

	dest = g_ptr_array_sized_new (src->len);
	for (i = 0; i < src->len; i++)
		g_ptr_array_add (dest, nm_ip6_address_dup (g_ptr_array_index (src, i)));
	return dest;
}

static void
_nm_ip6_address_object_array_free (GPtrArray *array)
{
	int i;

	for (i = 0; i < array->len; i++)
		nm_ip6_address_unref (g_ptr_array_index (array, i));
	g_ptr_array_free (array, TRUE);
}

GType
nm_ip6_address_object_array_get_type (void)
{
	static GType our_type = 0;

	if (our_type == 0)
		our_type = g_boxed_type_register_static (g_intern_static_string ("NMIP6AddressObjectArray"),
		                                         (GBoxedCopyFunc) _nm_ip6_address_object_array_copy,
		                                         (GBoxedFreeFunc) _nm_ip6_address_object_array_free);
	return our_type;
}

/*****************************/

static gpointer
_nm_ip6_address_array_copy (GPtrArray *src)
{
	GPtrArray *dest;
	int i;

	dest = g_ptr_array_sized_new (src->len);
	for (i = 0; i < src->len; i++) {
		struct in6_addr *addr = g_ptr_array_index (src, i);
		struct in6_addr *copy;

		copy = g_malloc0 (sizeof (struct in6_addr));
		memcpy (copy, addr, sizeof (struct in6_addr));
		g_ptr_array_add (dest, copy);
	}
	return dest;
}

static void
_nm_ip6_address_array_free (GPtrArray *array)
{
	int i;

	for (i = 0; i < array->len; i++)
		g_free (g_ptr_array_index (array, i));
	g_ptr_array_free (array, TRUE);
}

GType
nm_ip6_address_array_get_type (void)
{
	static GType our_type = 0;

	if (our_type == 0)
		our_type = g_boxed_type_register_static (g_intern_static_string ("NMIP6AddressArray"),
		                                         (GBoxedCopyFunc) _nm_ip6_address_array_copy,
		                                         (GBoxedFreeFunc) _nm_ip6_address_array_free);
	return our_type;
}

gboolean
_nm_ip6_address_array_demarshal (GValue *value, GSList **dest)
{
	GPtrArray *array;

	if (!G_VALUE_HOLDS (value, DBUS_TYPE_G_ARRAY_OF_ARRAY_OF_UCHAR))
		return FALSE;

	if (*dest) {
		g_slist_free_full (*dest, g_free);
		*dest = NULL;
	}

	array = (GPtrArray *) g_value_get_boxed (value);
	if (array && array->len) {
		int i;

		for (i = 0; i < array->len; i++) {
			GByteArray *bytearray = (GByteArray *) g_ptr_array_index (array, i);
			struct in6_addr *addr;

			addr = g_malloc0 (sizeof (struct in6_addr));
			memcpy (addr->s6_addr, bytearray->data, bytearray->len);
			*dest = g_slist_append (*dest, addr);
		}
	}

	return TRUE;
}

/*****************************/

static gpointer
_nm_ip6_route_object_array_copy (GPtrArray *src)
{
	GPtrArray *dest;
	int i;

	dest = g_ptr_array_sized_new (src->len);
	for (i = 0; i < src->len; i++)
		g_ptr_array_add (dest, nm_ip6_route_dup (g_ptr_array_index (src, i)));
	return dest;
}

static void
_nm_ip6_route_object_array_free (GPtrArray *array)
{
	int i;

	for (i = 0; i < array->len; i++)
		nm_ip6_route_unref (g_ptr_array_index (array, i));
	g_ptr_array_free (array, TRUE);
}

GType
nm_ip6_route_object_array_get_type (void)
{
	static GType our_type = 0;

	if (our_type == 0)
		our_type = g_boxed_type_register_static (g_intern_static_string ("NMIP6RouteObjectArray"),
		                                         (GBoxedCopyFunc) _nm_ip6_route_object_array_copy,
		                                         (GBoxedFreeFunc) _nm_ip6_route_object_array_free);
	return our_type;
}
