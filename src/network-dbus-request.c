/*
 * Network Client Library
 *
 * Copyright 2012 Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include <arpa/inet.h>
#include <netinet/in.h>

#include "network-internal.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * Macros and Typedefs
 *****************************************************************************/
#define DBUS_REPLY_TIMEOUT (120 * 1000)

/*****************************************************************************
 * Extern Variables
 *****************************************************************************/
extern __thread network_info_t NetworkInfo;
extern __thread network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

static int __net_error_string_to_enum(const char *error)
{
	NETWORK_LOG(NETWORK_LOW, "Passed error value [%s]", error);

	if (NULL != strstr(error, "NoReply"))
		return NET_ERR_TIME_OUT;
	else if (NULL != strstr(error, "Failed"))
		return NET_ERR_UNKNOWN;
	else if (NULL != strstr(error, "UnknownMethod"))
		return NET_ERR_UNKNOWN_METHOD;
	else if (NULL != strstr(error, "InvalidArguments"))
		return NET_ERR_INVALID_PARAM;
	else if (NULL != strstr(error, "AccessDenied"))
		return NET_ERR_ACCESS_DENIED;
	else if (NULL != strstr(error, "PermissionDenied"))
		return NET_ERR_ACCESS_DENIED;
	else if (NULL != strstr(error, "PassphraseRequired"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, "NotRegistered"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, "NotUnique"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, "NotSupported"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "NotImplemented"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "NotFound"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "NoCarrier"))
		return NET_ERR_NOT_SUPPORTED;
	else if (NULL != strstr(error, "InProgress"))
		return NET_ERR_IN_PROGRESS;
	else if (NULL != strstr(error, "AlreadyExists"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, "AlreadyEnabled"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, "AlreadyDisabled"))
		return NET_ERR_INVALID_OPERATION;
	else if (NULL != strstr(error, "AlreadyConnected"))
		return NET_ERR_ACTIVE_CONNECTION_EXISTS;
	else if (NULL != strstr(error, "NotConnected"))
		return NET_ERR_NO_ACTIVE_CONNECTIONS;
	else if (NULL != strstr(error, "OperationAborted"))
		return NET_ERR_OPERATION_ABORTED;
	else if (NULL != strstr(error, "OperationTimeout"))
		return NET_ERR_TIME_OUT;
	else if (NULL != strstr(error, "InvalidService"))
		return NET_ERR_NO_SERVICE;
	else if (NULL != strstr(error, "InvalidProperty"))
		return NET_ERR_INVALID_OPERATION;
	return NET_ERR_UNKNOWN;
}

static int __net_netconfig_error_string_to_enum(const char* error)
{
	NETWORK_LOG(NETWORK_ERROR, "Passed error value [%s]", error);

	if (error == NULL)
		return NET_ERR_UNKNOWN;

	if (NULL != strstr(error, ".WifiDriverFailed"))
		return NET_ERR_WIFI_DRIVER_FAILURE;
	else if (NULL != strstr(error, ".PermissionDenied"))
		return NET_ERR_SECURITY_RESTRICTED;
	else if (NULL != strstr(error, ".InProgress"))
		return NET_ERR_WIFI_DRIVER_LOAD_INPROGRESS;
	else if (NULL != strstr(error, ".AccessDenied"))
		return NET_ERR_ACCESS_DENIED;
	return NET_ERR_UNKNOWN;
}

static void __net_open_connection_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = { 0, };
	net_profile_info_t prof_info;
	network_request_table_t *open_info =
			&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION];
	network_request_table_t *wps_info =
			&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS];
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_LOW, "__net_open_connection_reply() called");

	conn = G_DBUS_CONNECTION(source_object);
	g_dbus_connection_call_finish(conn, res, &error);

	if (error != NULL) {
		Error = __net_error_string_to_enum(error->message);
		g_error_free(error);
	}

	if (Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR, "Connection open failed[%d]", Error);

	if (open_info->flag == TRUE) {
		net_device_t device_type =
				_net_get_tech_type_from_path(open_info->ProfileName);

		if (Error == NET_ERR_IN_PROGRESS && device_type == NET_DEVICE_CELLULAR)
			goto done;

		g_strlcpy(event_data.ProfileName, open_info->ProfileName,
				NET_PROFILE_NAME_LEN_MAX + 1);
		memset(open_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS) {
			Error = net_get_profile_info(event_data.ProfileName, &prof_info);

			if (device_type == NET_DEVICE_CELLULAR)
				event_data.Error = NET_ERR_NONE;

			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Fail to get profile info[%s]",
						_net_print_error(Error));

				event_data.Datalength = 0;
				event_data.Data = NULL;
			} else {
				event_data.Datalength = sizeof(net_profile_info_t);
				event_data.Data = &prof_info;
			}
		}

		event_data.Event = NET_EVENT_OPEN_RSP;
		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP Error[%s]",
				_net_print_error(event_data.Error));
	} else if (wps_info->flag == TRUE) {
		g_strlcpy(event_data.ProfileName, wps_info->ProfileName,
				NET_PROFILE_NAME_LEN_MAX + 1);
		memset(wps_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS) {
			Error = net_get_profile_info(event_data.ProfileName, &prof_info);
			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Fail to get profile info[%s]",
						_net_print_error(Error));

				event_data.Datalength = 0;
				event_data.Data = NULL;
			} else {
				event_data.Datalength = sizeof(net_profile_info_t);
				event_data.Data = &prof_info;
			}
		}

		event_data.Event = NET_EVENT_WIFI_WPS_RSP;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP Error[%s]",
				_net_print_error(event_data.Error));
	} else {
		_net_dbus_pending_call_unref();

		__NETWORK_FUNC_EXIT__;
		return;
	}

done:
	_net_dbus_pending_call_unref();

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_close_connection_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_close_connection_reply() called");

	net_event_info_t event_data = { 0, };
	network_request_table_t *close_info =
			&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION];

	GDBusConnection *conn = NULL;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;

	conn = G_DBUS_CONNECTION(source_object);
	g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		Error = __net_error_string_to_enum(error->message);
		g_error_free(error);
	}

	if (Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR, "Connection close failed[%d]", Error);

	if (close_info->flag == TRUE) {
		net_device_t device_type =
				_net_get_tech_type_from_path(close_info->ProfileName);

		if (Error == NET_ERR_ACTIVE_CONNECTION_EXISTS &&
				device_type == NET_DEVICE_CELLULAR)
			Error = NET_ERR_NONE;

		g_strlcpy(event_data.ProfileName, close_info->ProfileName,
				NET_PROFILE_NAME_LEN_MAX + 1);
		memset(close_info, 0, sizeof(network_request_table_t));

		event_data.Error = Error;
		event_data.Datalength = 0;
		event_data.Data = NULL;
		event_data.Event = NET_EVENT_CLOSE_RSP;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_RSP Error[%s]",
				_net_print_error(event_data.Error));
	} else {
		_net_dbus_pending_call_unref();

		__NETWORK_FUNC_EXIT__;
		return;
	}

done:
	_net_dbus_pending_call_unref();

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_wifi_power_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *conn = NULL;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;
	net_event_info_t event_data = { 0, };

	NETWORK_LOG(NETWORK_LOW, "__net_wifi_power_reply() called");

	conn = G_DBUS_CONNECTION(source_object);
	g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		Error = __net_netconfig_error_string_to_enum(error->message);
		g_error_free(error);
	}

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Wi-Fi power operation failed. Error [%d]", Error);

		if (Error != NET_ERR_WIFI_DRIVER_LOAD_INPROGRESS) {
			if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
				memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER],
						0, sizeof(network_request_table_t));

				event_data.Event = NET_EVENT_WIFI_POWER_RSP;

				NETWORK_LOG(NETWORK_LOW,
						"Sending NET_EVENT_WIFI_POWER_RSP Wi-Fi: %d Error = %d",
						NetworkInfo.wifi_state, Error);

				event_data.Datalength = sizeof(net_wifi_state_t);
				event_data.Data = &(NetworkInfo.wifi_state);
				event_data.Error = Error;
			}
		}
	} else {
		_net_dbus_pending_call_unref();

		__NETWORK_FUNC_EXIT__;
		return;
	}

	_net_dbus_pending_call_unref();

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_reset_cellular_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	int rv;
	net_event_info_t event_data = { 0, };
	GDBusConnection *conn = NULL;
	GVariant *dbus_result;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_LOW, "__net_reset_cellular_reply() called");

	conn = G_DBUS_CONNECTION(source_object);
	dbus_result = g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		Error = __net_error_string_to_enum(error->message);
		g_error_free(error);

		NETWORK_LOG(NETWORK_ERROR, "Error code: [%d]", Error);
	}

	if (request_table[NETWORK_REQUEST_TYPE_RESET_DEFAULT].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_RESET_DEFAULT],
						0, sizeof(network_request_table_t));
		event_data.Event = NET_EVENT_CELLULAR_RESET_DEFAULT_RSP;

		if (Error == NET_ERR_NONE) {
			g_variant_get(dbus_result, "(b)", &rv);

			NETWORK_LOG(NETWORK_LOW, "Reply: %s", rv ? "TRUE" : "FALSE");

			if (rv)
				event_data.Error = NET_ERR_NONE;
			else
				event_data.Error = NET_ERR_UNKNOWN;
		} else
			event_data.Error = Error;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CELLULAR_RESET_DEFAULT_RSP Error = %s",
				_net_print_error(event_data.Error));
	} else {
		_net_dbus_pending_call_unref();

		__NETWORK_FUNC_EXIT__;
		return;
	}

	_net_dbus_pending_call_unref();

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_specific_scan_wifi_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *conn = NULL;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;
	net_event_info_t event_data = { 0, };

	conn = G_DBUS_CONNECTION(source_object);
	g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		Error = __net_netconfig_error_string_to_enum(error->message);
		g_error_free(error);
	}

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "Find specific AP failed[%d]", Error);
	else
		NETWORK_LOG(NETWORK_LOW, "Specific AP found");

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		if (NET_ERR_NONE != Error) {
			/* An error occurred.
			 * So lets reset specific scan request entry in the request table */
			memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN],
					0, sizeof(network_request_table_t));
		}

		event_data.Event = NET_EVENT_SPECIFIC_SCAN_RSP;

		NETWORK_LOG(NETWORK_LOW,
				"Sending NET_EVENT_SPECIFIC_SCAN_RSP Wi-Fi: %d Error[%d]",
				NetworkInfo.wifi_state, Error);

		event_data.Datalength = sizeof(net_wifi_state_t);
		event_data.Data = &(NetworkInfo.wifi_state);
		event_data.Error = Error;

		_net_dbus_pending_call_unref();
		_net_client_callback(&event_data);
	} else {
		_net_dbus_pending_call_unref();
		__NETWORK_FUNC_EXIT__;
		return;
	}

	__NETWORK_FUNC_EXIT__;
}

static void __net_wps_scan_wifi_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *conn = NULL;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;
	net_event_info_t event_data = { 0, };

	conn = G_DBUS_CONNECTION(source_object);
	g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		Error = __net_netconfig_error_string_to_enum(error->message);
		g_error_free(error);
	}

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "WPS scan failed[%d]", Error);

		if (request_table[NETWORK_REQUEST_TYPE_WPS_SCAN].flag == TRUE) {
			memset(&request_table[NETWORK_REQUEST_TYPE_WPS_SCAN],
					0, sizeof(network_request_table_t));

			event_data.Event = NET_EVENT_WPS_SCAN_IND;
			event_data.Datalength = 0;
			event_data.Data = NULL;
			event_data.Error = Error;

			_net_dbus_pending_call_unref();

			_net_client_callback(&event_data);

			__NETWORK_FUNC_EXIT__;
			return;
		}
	} else
		NETWORK_LOG(NETWORK_LOW, "WPS scan succeed");

	_net_dbus_pending_call_unref();

	__NETWORK_FUNC_EXIT__;
}

static void __net_set_passpoint_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *conn = NULL;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;

	conn = G_DBUS_CONNECTION(source_object);
	g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		Error = __net_netconfig_error_string_to_enum(error->message);
		g_error_free(error);
	}

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "set passpoint failed[%d]", Error);
	else
		NETWORK_LOG(NETWORK_LOW, "set passpoint succeeded");

	_net_dbus_pending_call_unref();

	__NETWORK_FUNC_EXIT__;
}

static void __net_set_default_reply(GObject *source_object, GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	int rv;
	net_event_info_t event_data = { 0, };
	GDBusConnection *conn = NULL;
	GVariant *dbus_result;
	GError *error = NULL;
	net_err_t Error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_LOW, "__net_set_default_reply() called");

	conn = G_DBUS_CONNECTION(source_object);
	dbus_result = g_dbus_connection_call_finish(conn, res, &error);
	if (error != NULL) {
		Error = __net_error_string_to_enum(error->message);
		g_error_free(error);

		NETWORK_LOG(NETWORK_ERROR, "Error code[%d]", Error);
	}

	if (request_table[NETWORK_REQUEST_TYPE_SET_DEFAULT].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SET_DEFAULT],
						0, sizeof(network_request_table_t));
		event_data.Event = NET_EVENT_CELLULAR_SET_DEFAULT_RSP;

		if (Error == NET_ERR_NONE) {
			g_variant_get(dbus_result, "(b)", &rv);

			NETWORK_LOG(NETWORK_LOW, "Reply: %s", rv ? "TRUE" : "FALSE");

			if (rv)
				event_data.Error = NET_ERR_NONE;
			else
				event_data.Error = NET_ERR_UNKNOWN;
		} else
			event_data.Error = Error;

		NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CELLULAR_SET_DEFAULT_RSP Error[%s]",
				_net_print_error(event_data.Error));
	} else {
		_net_dbus_pending_call_unref();

		__NETWORK_FUNC_EXIT__;
		return;
	}

	_net_dbus_pending_call_unref();

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static char *__net_make_group_name(const char *ssid,
		const char *net_mode, const char *sec)
{
	char *buf = NULL;
	char *pbuf = NULL;
	const char *hidden_str = "hidden";
	const char *g_sec;
	char buf_tmp[32] = { 0, };
	int i;
	int ssid_len = 0;
	int actual_len = 0;

	if (net_mode == NULL || sec == NULL)
		return NULL;

	if (NULL != ssid) {
		ssid_len = strlen(ssid);
		actual_len = ssid_len * 2;
	} else {
		ssid_len = strlen(hidden_str);
		actual_len = ssid_len;
	}

	if (g_strcmp0(net_mode, "managed") != 0)
		return NULL;

	if (!g_strcmp0(sec, "wpa") || !g_strcmp0(sec, "rsn"))
		g_sec = "psk";
	else
		g_sec = sec;

	buf = g_try_malloc0(actual_len + strlen(net_mode) + strlen(sec) + 3);
	if (buf == NULL)
		return NULL;

	if (NULL != ssid) {
		pbuf = buf;
		for (i = 0; i < ssid_len; i++) {
			g_snprintf(pbuf, 3, "%02x", ssid[i]);
			pbuf += 2;
		}
	} else
		g_strlcat(buf, hidden_str,
				actual_len + strlen(net_mode) + strlen(sec) + 3);

	g_snprintf(buf_tmp, 32, "_%s_%s", net_mode, g_sec);
	g_strlcat(buf, buf_tmp,
			actual_len + strlen(net_mode) + strlen(sec) + 3);

	NETWORK_LOG(NETWORK_LOW, "Group name: %s", buf);

	return buf;
}

static int __net_dbus_set_agent_field_and_connect(
		const char *key, const char *value, const char *profilename)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *params = NULL;
	GVariantBuilder *builder;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", key, g_variant_new_string(value));

	params = g_variant_new("(o@a{sv})",
			profilename, g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH,
			CONNMAN_AGENT_INTERFACE, "SetField", params,
			DBUS_REPLY_TIMEOUT, __net_open_connection_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/*****************************************************************************
 * Global Functions Definition
 *****************************************************************************/
GVariant *_net_invoke_dbus_method(const char *dest, const char *path,
		const char *interface_name, const char *method,
		GVariant *params, int *dbus_error)
{
	__NETWORK_FUNC_ENTER__;

	GError *error = NULL;
	GVariant *reply = NULL;
	*dbus_error = NET_ERR_NONE;
	GDBusConnection *connection;

	connection = _net_dbus_get_gdbus_conn();
	if (connection == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "GDBusconnection is NULL");
		*dbus_error = NET_ERR_APP_NOT_REGISTERED;
		return reply;
	}

	reply = g_dbus_connection_call_sync(connection,
			dest,
			path,
			interface_name,
			method,
			params,
			NULL,
			G_DBUS_CALL_FLAGS_NONE,
			DBUS_REPLY_TIMEOUT,
			_net_dbus_get_gdbus_cancellable(),
			&error);
	if (reply == NULL) {
		if (error != NULL) {
			SECURE_NETWORK_LOG(NETWORK_ERROR,
						"g_dbus_connection_call_sync() failed"
						"error [%d: %s]", error->code, error->message);
			*dbus_error = __net_error_string_to_enum(error->message);
			g_error_free(error);
		} else {
			NETWORK_LOG(NETWORK_ERROR,
					"g_dbus_connection_call_sync() failed");
			*dbus_error = NET_ERR_UNKNOWN;
		}

		__NETWORK_FUNC_EXIT__;
		return NULL;
	}

	__NETWORK_FUNC_EXIT__;
	return reply;
}

int _net_invoke_dbus_method_nonblock(const char *dest, const char *path,
		const char *interface_name, const char *method,
		GVariant *params, int timeout,
		GAsyncReadyCallback notify_func)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *connection;

	connection = _net_dbus_get_gdbus_conn();
	if (connection == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "GDBusconnection is NULL");
		return NET_ERR_APP_NOT_REGISTERED;
	}

	g_dbus_connection_call(connection,
							dest,
							path,
							interface_name,
							method,
							params,
							NULL,
							G_DBUS_CALL_FLAGS_NONE,
							timeout,
							_net_dbus_get_gdbus_cancellable(),
							(GAsyncReadyCallback) notify_func,
							NULL);

	if (notify_func != NULL)
		_net_dbus_pending_call_ref();

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_open_connection(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	/* use DBus signal than reply pending because of performance reason */
	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "Connect", NULL,
			DBUS_REPLY_TIMEOUT, __net_open_connection_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_close_connection(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	/* use DBus signal than reply pending because of performance reason */
	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "Disconnect", NULL,
			DBUS_REPLY_TIMEOUT, __net_close_connection_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_scan_request(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	/* use DBus signal than reply pending because of performance reason */
	Error = _net_invoke_dbus_method_nonblock(CONNMAN_SERVICE,
			CONNMAN_WIFI_TECHNOLOGY_PREFIX,
			CONNMAN_TECHNOLOGY_INTERFACE, "Scan", NULL,
			DBUS_REPLY_TIMEOUT, NULL);

	if (Error == NET_ERR_IN_PROGRESS)
		Error = NET_ERR_NONE;

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_default(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(TELEPHONY_SERVICE,
			profile_name, TELEPHONY_PROFILE_INTERFACE,
			"SetDefaultConnection", NULL, DBUS_REPLY_TIMEOUT,
			__net_set_default_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_bgscan_mode(net_wifi_background_scan_mode_t mode)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	GVariant *params;

	char path[CONNMAN_MAX_BUFLEN] = NETCONFIG_WIFI_PATH;

	params = g_variant_new("(u)", mode);

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, path,
			NETCONFIG_WIFI_INTERFACE, "SetBgscan", params, &Error);

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "_net_invoke_dbus_method failed");

	if (message != NULL)
		g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_technology_state(network_tech_state_info_t* tech_state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	if ((tech_state == NULL) || (strlen(tech_state->technology) == 0)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetTechnologies", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get technology info");
		goto done;
	}

	Error = _net_get_tech_state(message, tech_state);

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_tech_state_info_t tech_state = {{0,},};

	if (device_type == NET_DEVICE_WIFI)
		g_strlcpy(tech_state.technology, "wifi", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_CELLULAR)
		g_strlcpy(tech_state.technology, "cellular", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_ETHERNET)
		g_strlcpy(tech_state.technology, "ethernet", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_BLUETOOTH)
		g_strlcpy(tech_state.technology, "bluetooth", NET_TECH_LENGTH_MAX);
	else {
		Error = NET_ERR_INVALID_PARAM;
		goto done;
	}

	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"_net_dbus_get_technology_state() failed. Error [%s]",
			_net_print_error(Error));
		goto done;
	}

	if (tech_state.Connected == TRUE)
		*network_status = NET_STATUS_AVAILABLE;
	else
		*network_status = NET_STATUS_UNAVAILABLE;

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_tech_status(net_device_t device_type, net_tech_info_t* tech_status)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_tech_state_info_t tech_state = {{0,},};

	if (device_type == NET_DEVICE_WIFI)
		g_strlcpy(tech_state.technology, "wifi", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_CELLULAR)
		g_strlcpy(tech_state.technology, "cellular", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_ETHERNET)
		g_strlcpy(tech_state.technology, "ethernet", NET_TECH_LENGTH_MAX);
	else if (device_type == NET_DEVICE_BLUETOOTH)
		g_strlcpy(tech_state.technology, "bluetooth", NET_TECH_LENGTH_MAX);
	else {
		Error = NET_ERR_INVALID_PARAM;
		goto done;
	}

	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"_net_dbus_get_technology_state() failed. Error [%s]",
			_net_print_error(Error));
		goto done;
	}

	if (tech_state.Powered == TRUE)
		tech_status->powered = TRUE;
	else
		tech_status->powered = FALSE;

	if (tech_state.Connected == TRUE)
		tech_status->connected = TRUE;
	else
		tech_status->connected = FALSE;

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_wifi_state(char **wifi_state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	const char *method = "GetWifiState";

	if (NULL == wifi_state) {
			NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(
			NETCONFIG_SERVICE, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, method, NULL, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get wifi state\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(message, "(s)", wifi_state);
	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;

	return Error;
}

int _net_dbus_get_statistics(net_device_t device_type, net_statistics_type_e statistics_type, unsigned long long *size)
{
	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	char *method = NULL;

	if (device_type == NET_DEVICE_WIFI) {
		switch (statistics_type) {
		case NET_STATISTICS_TYPE_LAST_RECEIVED_DATA:
			method = "GetWifiLastRxBytes";
			break;
		case NET_STATISTICS_TYPE_LAST_SENT_DATA:
			method = "GetWifiLastTxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_RECEIVED_DATA:
			method = "GetWifiTotalRxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_SENT_DATA:
			method = "GetWifiTotalTxBytes";
			break;
		default:
			NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
			return NET_ERR_INVALID_PARAM;
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
		return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(
			NETCONFIG_SERVICE, NETCONFIG_STATISTICS_PATH,
			NETCONFIG_STATISTICS_INTERFACE, method, NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service properties");
		return Error;
	}

	g_variant_get(message, "(t)", size);

	NETWORK_LOG(NETWORK_LOW, "success [%s] statistics size: [%llu]", method, *size);
	g_variant_unref(message);

	return Error;
}

int _net_dbus_set_statistics(net_device_t device_type, net_statistics_type_e statistics_type)
{
	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	char *method = NULL;

	if (device_type == NET_DEVICE_CELLULAR) {
		switch (statistics_type) {
		case NET_STATISTICS_TYPE_LAST_RECEIVED_DATA:
			method = "ResetCellularLastRxBytes";
			break;
		case NET_STATISTICS_TYPE_LAST_SENT_DATA:
			method = "ResetCellularLastTxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_RECEIVED_DATA:
			method = "ResetCellularTotalRxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_SENT_DATA:
			method = "ResetCellularTotalTxBytes";
			break;
		default:
			NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
			return NET_ERR_INVALID_PARAM;
		}
	} else if (device_type == NET_DEVICE_WIFI) {
		switch (statistics_type) {
		case NET_STATISTICS_TYPE_LAST_RECEIVED_DATA:
			method = "ResetWifiLastRxBytes";
			break;
		case NET_STATISTICS_TYPE_LAST_SENT_DATA:
			method = "ResetWifiLastTxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_RECEIVED_DATA:
			method = "ResetWifiTotalRxBytes";
			break;
		case NET_STATISTICS_TYPE_TOTAL_SENT_DATA:
			method = "ResetWifiTotalTxBytes";
			break;
		default:
			NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
			return NET_ERR_INVALID_PARAM;
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
		return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(
			NETCONFIG_SERVICE, NETCONFIG_STATISTICS_PATH,
			NETCONFIG_STATISTICS_INTERFACE, method, NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service properties");
		return Error;
	}

	NETWORK_LOG(NETWORK_LOW, "reset [%s] statistics success", method);
	g_variant_unref(message);

	return Error;
}

int _net_dbus_get_state(char* state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	GVariant *value = NULL;
	GVariantIter *iter = NULL;
	gchar *key = NULL;
	const gchar *net_state = NULL;

	message = _net_invoke_dbus_method(
			CONNMAN_SERVICE, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetProperties", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service properties");

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(message, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "State") == 0) {
			net_state = g_variant_get_string(value, NULL);
			g_strlcpy(state, net_state, CONNMAN_STATE_STRLEN);
			g_variant_unref(value);
			g_free(key);
			break;
		}
	}

	NETWORK_LOG(NETWORK_LOW, "State: %s", state);

	g_variant_iter_free(iter);
	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_ethernet_cable_state(int *state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	if (state == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "EthernetCableState", NULL, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get Ethernet Module State\n");
		return Error;
	}

	g_variant_get(message, "(i)", state);

	NETWORK_LOG(NETWORK_LOW, "Ethernet Cable State [%d]\n", *state);

	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_eap_config_fields_and_connect(
		const net_wifi_connect_service_info_t *wifi_info,
		const char *profilename)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *params = NULL;
	GVariantBuilder *builder;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{ss}"));
	g_variant_builder_add(builder, "{ss}", CONNMAN_CONFIG_FIELD_TYPE, "wifi");

	if (wifi_info->ssid)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_NAME, wifi_info->ssid);

	if (wifi_info->eap_type)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_EAP_METHOD, wifi_info->eap_type);

	if (wifi_info->eap_keymgmt_type)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_EAP_KEYMGMT_TYPE, wifi_info->eap_keymgmt_type);

	if (wifi_info->identity)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_IDENTITY, wifi_info->identity);

	if (wifi_info->password)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_PASSPHRASE, wifi_info->password);

	if (wifi_info->eap_auth &&
			g_strcmp0(wifi_info->eap_auth, "NONE") != 0)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_PHASE2, wifi_info->eap_auth);

	if (wifi_info->ca_cert_file)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_CA_CERT_FILE, wifi_info->ca_cert_file);

	if (wifi_info->client_cert_file)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE,
				wifi_info->client_cert_file);

	if (wifi_info->private_key_file)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_PVT_KEY_FILE,
				wifi_info->private_key_file);

	if (wifi_info->private_key_password)
		g_variant_builder_add(builder, "{ss}",
				CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE,
				wifi_info->private_key_password);

	params = g_variant_new("(o@a{ss})",
			profilename, g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, "CreateEapConfig", params,
			DBUS_REPLY_TIMEOUT, __net_open_connection_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_agent_passphrase_and_connect(
		const char *passphrase, const char *profilename)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NULL == passphrase || strlen(passphrase) <= 0 || NULL == profilename) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_dbus_set_agent_field_and_connect(
			NETCONFIG_AGENT_FIELD_PASSPHRASE,
			passphrase,
			profilename);
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR, "Configuration failed(%d)", Error);
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_agent_fields_and_connect(const char *ssid,
		const char *passphrase, const char *profilename)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	/* If OPEN network, passphrase can be NULL */
	if (NULL == ssid || strlen(ssid) <= 0 || NULL == profilename) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		return NET_ERR_INVALID_PARAM;
	}

	GVariant *params = NULL;
	GVariantBuilder *builder;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));
	g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_SSID,
			g_variant_new_fixed_array(G_VARIANT_TYPE_BYTE, ssid,
					strlen(ssid), sizeof(guchar)));

	if (passphrase)
		g_variant_builder_add(builder, "{sv}", NETCONFIG_AGENT_FIELD_PASSPHRASE,
				g_variant_new_string(passphrase));

	params = g_variant_new("(o@a{sv})",
			profilename, g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH,
			CONNMAN_AGENT_INTERFACE, "SetField", params,
			DBUS_REPLY_TIMEOUT, __net_open_connection_reply);
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR, "Configuration failed(%d)", Error);
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_wps_pin(char **wps_pin)
{
	__NETWORK_FUNC_ENTER__;
	net_err_t error = NET_ERR_NONE;
	GVariant *params = NULL;
	GVariant *reply = NULL;
	gchar *value = NULL;
	char *path = NULL;

	params = g_variant_new("(s)", "wlan0");
	reply = _net_invoke_dbus_method(SUPPLICANT_SERVICE, SUPPLICANT_PATH,
			SUPPLICANT_INTERFACE, "GetInterface", params, &error);
	if (reply == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get Wi-Fi interface");
		return error;
	}
	g_variant_get(reply, "(o)", &path);

	reply = _net_invoke_dbus_method(SUPPLICANT_SERVICE, path,
			SUPPLICANT_INTERFACE ".Interface.WPS", "GetPin", NULL, &error);
	if (reply == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get wps pin");
		return error;
	}
	g_variant_get(reply, "(s)", &value);
	*wps_pin = g_strdup_printf("%s", value);
	g_variant_unref(reply);

	__NETWORK_FUNC_EXIT__;
	return error;
}

int _net_dbus_set_agent_wps_pbc_and_connect(const char *profilename)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = __net_dbus_set_agent_field_and_connect(
			NETCONFIG_AGENT_FIELD_WPS_PBC,
			"enable",
			profilename);
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR, "PBC configuration failed(%d)", Error);
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_agent_wps_pin_and_connect(
		const char *wps_pin, const char *profilename)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NULL == wps_pin || strlen(wps_pin) <= 0) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid param ");
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_dbus_set_agent_field_and_connect(
			NETCONFIG_AGENT_FIELD_WPS_PIN,
			wps_pin,
			profilename);
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR, "PIN configuration failed(%d)", Error);
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_connect_service(const net_wifi_connect_service_info_t *wifi_connection_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	char *grp_name = NULL;
	int profile_count = 0;
	net_profile_info_t* profile_info = NULL;
	int i = 0;

	/* Get group name with prefix 'ssid' in hex */
	grp_name = __net_make_group_name(wifi_connection_info->is_hidden == TRUE ?
				NULL : wifi_connection_info->ssid,
			wifi_connection_info->mode,
			wifi_connection_info->security);
	if (NULL == grp_name) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to make a group name");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	Error = _net_get_profile_list(NET_DEVICE_WIFI, &profile_info, &profile_count);
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_get_profile_list fail. Error [%s]",
				_net_print_error(Error));

		goto error;
	}

	for (i = 0; i < profile_count; i++) {
		if (g_strstr_len(profile_info[i].ProfileName,
				NET_PROFILE_NAME_LEN_MAX+1, grp_name) != NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Found profile %s",
					profile_info[i].ProfileName);

			if (profile_info[i].ProfileState == NET_STATE_TYPE_READY ||
					profile_info[i].ProfileState == NET_STATE_TYPE_ONLINE) {
				NETWORK_LOG(NETWORK_ERROR, "Already profile is connected");
				Error = NET_ERR_ACTIVE_CONNECTION_EXISTS;

				goto error;
			}

			break;
		}
	}

	if (i >= profile_count) {
		NETWORK_LOG(NETWORK_ERROR, "No matching profile found");
		Error = NET_ERR_NO_SERVICE;

		goto error;
	}

	if (wifi_connection_info->is_hidden == TRUE) {
		int target = 0;
		char *target_name = __net_make_group_name(wifi_connection_info->ssid,
				wifi_connection_info->mode,
				wifi_connection_info->security);

		for (target = 0; target < profile_count; target++) {
			if (g_strstr_len(profile_info[target].ProfileName,
					NET_PROFILE_NAME_LEN_MAX+1, target_name) != NULL) {
				g_strlcpy(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
						profile_info[target].ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

				break;
			}
		}

		g_free(target_name);
	} else {
		g_strlcpy(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
				profile_info[i].ProfileName, NET_PROFILE_NAME_LEN_MAX+1);
	}

	if (g_strcmp0(wifi_connection_info->security, "ieee8021x") == 0) {
		/* Create the EAP config file */
		Error = _net_dbus_set_eap_config_fields_and_connect(
				wifi_connection_info, profile_info[i].ProfileName);
		if (NET_ERR_NONE != Error) {
			NETWORK_LOG(NETWORK_ERROR, "Fail to create eap_config");

			goto error;
		}
	} else if (wifi_connection_info->is_hidden == TRUE) {
		Error = _net_dbus_set_agent_fields_and_connect(
				wifi_connection_info->ssid,
				wifi_connection_info->passphrase,
				profile_info[i].ProfileName);
	} else if (g_strcmp0(wifi_connection_info->security, "none") != 0) {
		Error = _net_dbus_set_agent_passphrase_and_connect(
				wifi_connection_info->passphrase, profile_info[i].ProfileName);
		if (NET_ERR_NONE != Error) {
			NETWORK_LOG(NETWORK_ERROR, "Fail to set agent_passphrase");

			goto error;
		}
	} else
		Error = _net_dbus_open_connection(profile_info[i].ProfileName);

error:
	if (NET_ERR_NONE != Error) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request open connection, Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
				0, sizeof(network_request_table_t));
	}

	NET_MEMFREE(profile_info);
	g_free(grp_name);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_profile_ipv4(net_profile_info_t* prof_info, char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	const char *manual_method = "manual";
	const char *dhcp_method = "dhcp";
	const char *off_method = "off";

	const char *prop_ipv4_configuration = "IPv4.Configuration";
	const char *prop_method = "Method";
	const char *prop_address = "Address";
	const char *prop_gateway = "Gateway";
	const char *prop_netmask = "Netmask";

	char ip_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";
	char netmask_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";
	char gateway_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";

	char *ipaddress = ip_buffer;
	char *netmask = netmask_buffer;
	char *gateway = gateway_buffer;

	GVariant *params = NULL;
	GVariantBuilder *builder;
	net_dev_info_t *profile_net_info  = NULL;

	GVariant *message = NULL;

	NETWORK_LOG(NETWORK_HIGH, "profile_name: [%s]", profile_name);

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (prof_info->profile_type == NET_DEVICE_WIFI)
		profile_net_info = &(prof_info->ProfileInfo.Wlan.net_info);
	else if (prof_info->profile_type == NET_DEVICE_ETHERNET)
		profile_net_info = &(prof_info->ProfileInfo.Ethernet.net_info);
	else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Profile Type\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	g_strlcpy(ip_buffer,
			inet_ntoa(profile_net_info->IpAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(netmask_buffer,
			inet_ntoa(profile_net_info->SubnetMask.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(gateway_buffer,
			inet_ntoa(profile_net_info->GatewayAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	SECURE_NETWORK_LOG(NETWORK_LOW, "ip: %s, netmask: %s, gateway: %s",
			ipaddress, netmask, gateway);

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	if (profile_net_info->IpConfigType == NET_IP_CONFIG_TYPE_DYNAMIC ||
	    profile_net_info->IpConfigType == NET_IP_CONFIG_TYPE_AUTO_IP) {

		g_variant_builder_add(builder, "{sv}", prop_method, g_variant_new_string(dhcp_method));

	} else if (profile_net_info->IpConfigType == NET_IP_CONFIG_TYPE_OFF) {

		g_variant_builder_add(builder, "{sv}", prop_method, g_variant_new_string(off_method));

	} else if (profile_net_info->IpConfigType == NET_IP_CONFIG_TYPE_STATIC) {

		g_variant_builder_add(builder, "{sv}", prop_method, g_variant_new_string(manual_method));

		if (strlen(ipaddress) >= NETPM_IPV4_STR_LEN_MIN)
			g_variant_builder_add(builder, "{sv}", prop_address, g_variant_new_string(ipaddress));

		if (strlen(netmask) >= NETPM_IPV4_STR_LEN_MIN)
			g_variant_builder_add(builder, "{sv}", prop_netmask, g_variant_new_string(netmask));

		if (strlen(gateway) >= NETPM_IPV4_STR_LEN_MIN)
			g_variant_builder_add(builder, "{sv}", prop_gateway, g_variant_new_string(gateway));

	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	params = g_variant_new("(sv)",
			prop_ipv4_configuration, g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "SetProperty", params,
			&Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to set IPv4 Property");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_unref(message);
	NETWORK_LOG(NETWORK_HIGH, "Successfully configured IPv4.Configuration\n");

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_profile_ipv6(net_profile_info_t* prof_info, char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	const char *manual_method = "manual";
	const char *auto_method = "auto";
	const char *off_method = "off";

	const char *prop_ipv6_configuration = "IPv6.Configuration";
	const char *prop_method = "Method";
	const char *prop_address = "Address";
	const char *prop_gateway = "Gateway";
	const char *prop_prefixlen = "PrefixLength";

	char ipaddr6[INET6_ADDRSTRLEN];
	char gwaddr6[INET6_ADDRSTRLEN];
	char prefixlen[INET6_ADDRSTRLEN];

	char *ip6_ptr = ipaddr6;
	char *gw6_ptr = gwaddr6;
	char *prlen_ptr = prefixlen;

	net_err_t Error = NET_ERR_NONE;
	GVariant *params = NULL;
	GVariantBuilder *builder;
	GVariant *message = NULL;
	net_dev_info_t *profile_net_info  = NULL;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (prof_info->profile_type == NET_DEVICE_WIFI)
		profile_net_info = &(prof_info->ProfileInfo.Wlan.net_info);
	else if (prof_info->profile_type == NET_DEVICE_ETHERNET)
		profile_net_info = &(prof_info->ProfileInfo.Ethernet.net_info);
	else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Profile Type\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	inet_ntop(AF_INET6, &profile_net_info->IpAddr6.Data.Ipv6, ipaddr6,
			INET6_ADDRSTRLEN);
	inet_ntop(AF_INET6, &profile_net_info->GatewayAddr6.Data.Ipv6, gwaddr6,
			INET6_ADDRSTRLEN);
	g_snprintf(prefixlen, INET6_ADDRSTRLEN, "%d",
			profile_net_info->PrefixLen6);

	NETWORK_LOG(NETWORK_HIGH, "ipaddress : %s, prefix_len : %s, gateway :"
			" %s\n", ip6_ptr, prlen_ptr, gw6_ptr);

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	if (profile_net_info->IpConfigType6 == NET_IP_CONFIG_TYPE_DYNAMIC ||
		profile_net_info->IpConfigType6 == NET_IP_CONFIG_TYPE_AUTO_IP) {

		g_variant_builder_add(builder, "{sv}", prop_method,
				g_variant_new_string(auto_method));

	} else if (profile_net_info->IpConfigType6 == NET_IP_CONFIG_TYPE_OFF) {

		g_variant_builder_add(builder, "{sv}", prop_method,
				g_variant_new_string(off_method));

		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2: %s %s\n",
				prop_method, off_method);
	} else if (profile_net_info->IpConfigType6 == NET_IP_CONFIG_TYPE_STATIC) {

		g_variant_builder_add(builder, "{sv}", prop_method,
				g_variant_new_string(manual_method));

		if (strlen(ipaddr6) >= NETPM_IPV6_STR_LEN_MIN) {
			g_variant_builder_add(builder, "{sv}", prop_address,
					g_variant_new_string(ip6_ptr));
		}

		if (profile_net_info->PrefixLen6 <= NETPM_IPV6_MAX_PREFIX_LEN) {
			g_variant_builder_add(builder, "{sv}", prop_prefixlen,
					g_variant_new_string(prlen_ptr));
		}

		if (strlen(gwaddr6) >= NETPM_IPV6_STR_LEN_MIN) {
			g_variant_builder_add(builder, "{sv}", prop_gateway,
					g_variant_new_string(gw6_ptr));
		}
		NETWORK_LOG(NETWORK_HIGH, "DBus Message 2/2: %s %s %s %s %s %s"
				" %s %s\n", prop_method, manual_method,
				prop_address, ipaddr6, prop_prefixlen,
				prefixlen, prop_gateway, gwaddr6);
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	params = g_variant_new("(sv)", prop_ipv6_configuration,
			g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "SetProperty", params,
			&Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to set IPv6 Property");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_unref(message);
	NETWORK_LOG(NETWORK_HIGH, "Successfully configured IPv6.Configuration\n");

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_profile_dns(net_profile_info_t* prof_info, char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	const char *prop_nameserver_configuration = "Nameservers.Configuration";
	char dns_buffer[NET_DNS_ADDR_MAX][NETPM_IPV4_STR_LEN_MAX+1];
	char *dns_address[NET_DNS_ADDR_MAX];
	net_err_t Error = NET_ERR_NONE;
	GVariant *params = NULL;
	GVariantBuilder *builder;
	int i = 0;
	net_dev_info_t *profile_net_info  = NULL;
	GVariant *message = NULL;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (prof_info->profile_type == NET_DEVICE_WIFI)
		profile_net_info = &(prof_info->ProfileInfo.Wlan.net_info);
	else if	(prof_info->profile_type == NET_DEVICE_ETHERNET)
		profile_net_info = &(prof_info->ProfileInfo.Ethernet.net_info);
	else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Profile Type\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}
	if (profile_net_info->DnsCount > NET_DNS_ADDR_MAX) {
			NETWORK_LOG(NETWORK_ERROR, "Invalid parameter\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_PARAM;
	}

	for (i = 0; i < profile_net_info->DnsCount; i++) {
		dns_buffer[i][0] = '\0';
		dns_address[i] = NULL;

		if (profile_net_info->DnsAddr[i].Data.Ipv4.s_addr != 0)
			g_strlcpy(dns_buffer[i],
					inet_ntoa(profile_net_info->DnsAddr[i].Data.Ipv4),
					NETPM_IPV4_STR_LEN_MAX + 1);

		dns_address[i] = dns_buffer[i];
	}

	if (profile_net_info->IpConfigType == NET_IP_CONFIG_TYPE_STATIC) {

		builder = g_variant_builder_new(G_VARIANT_TYPE("as"));
		for (i = 0; i < profile_net_info->DnsCount; i++)
			g_variant_builder_add(builder, "s", dns_address[i]);

		params = g_variant_new("(sv)", prop_nameserver_configuration, g_variant_builder_end(builder));
		g_variant_builder_unref(builder);

		message = _net_invoke_dbus_method(CONNMAN_SERVICE, profile_name,
				CONNMAN_SERVICE_INTERFACE, "SetProperty", params,
				&Error);
		if (message == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to set "
					"Nameservers.Configuration");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
		NETWORK_LOG(NETWORK_HIGH, "Successfully configured Nameservers.Configuration\n");
		g_variant_unref(message);
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_proxy(net_profile_info_t* prof_info, char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	const char *direct_method = "direct";
	const char *auto_method = "auto";
	const char *manual_method = "manual";

	const char *prop_proxy_configuration = "Proxy.Configuration";
	const char *prop_method = "Method";
	const char *prop_url = "URL";
	const char *prop_servers = "Servers";

	char proxy_buffer[NET_PROXY_LEN_MAX+1] = "";
	char *proxy_address = proxy_buffer;

	GVariant *params = NULL;
	GVariantBuilder *builder;
	GVariantBuilder *builder_sub;
	net_dev_info_t *profile_net_info  = NULL;

	GVariant *message = NULL;

	if ((prof_info == NULL) || (profile_name == NULL) || (strlen(profile_name) == 0)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (prof_info->profile_type == NET_DEVICE_WIFI)
		profile_net_info = &(prof_info->ProfileInfo.Wlan.net_info);
	else if (prof_info->profile_type == NET_DEVICE_ETHERNET)
		profile_net_info = &(prof_info->ProfileInfo.Ethernet.net_info);
	else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Profile Type\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	g_strlcpy(proxy_buffer,
			profile_net_info->ProxyAddr, NET_PROXY_LEN_MAX+1);

	SECURE_NETWORK_LOG(NETWORK_LOW, "method: %d, proxy address: %s, Profile Name %s",
			profile_net_info->ProxyMethod, proxy_address, profile_net_info->ProfileName);

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{sv}"));

	switch (profile_net_info->ProxyMethod) {
	case NET_PROXY_TYPE_AUTO:
		g_variant_builder_add(builder, "{sv}", prop_method, g_variant_new_string(auto_method));
		break;
	case NET_PROXY_TYPE_MANUAL:
		g_variant_builder_add(builder, "{sv}", prop_method, g_variant_new_string(manual_method));
		break;
	default:
		g_variant_builder_add(builder, "{sv}", prop_method, g_variant_new_string(direct_method));
		break;
	}

	if (profile_net_info->ProxyMethod == NET_PROXY_TYPE_AUTO &&
			proxy_address[0] != '\0') {
		g_variant_builder_add(builder, "{sv}", prop_url, g_variant_new_string(proxy_address));
	}

	if (profile_net_info->ProxyMethod == NET_PROXY_TYPE_MANUAL &&
			proxy_address[0] != '\0') {
		builder_sub = g_variant_builder_new(G_VARIANT_TYPE("as"));
		g_variant_builder_add(builder_sub, "s", proxy_address);
		g_variant_builder_add(builder, "{sv}", prop_servers, g_variant_builder_end(builder_sub));
		g_variant_builder_unref(builder_sub);
	}

	params = g_variant_new("(sv)", prop_proxy_configuration, g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, profile_name,
			CONNMAN_SERVICE_INTERFACE, "SetProperty", params,
			&Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to set Proxy Configuration");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}
	NETWORK_LOG(NETWORK_HIGH, "Successfully configured Proxy.Configuration\n");
	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_add_pdp_profile(net_profile_info_t *prof_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	const char *service_type = "svc_ctg_id";
	const char *home_url = "home_url";
	const char *proxy_addr = "proxy_addr";
	const char *auth_pwd = "auth_pwd";
	const char *auth_type = "auth_type";
	const char *auth_id = "auth_id";
	const char *apn = "apn";
	const char *keyword = "profile_name";

	char buff_svc_type[10] = "";
	char buff_auth_type[10] = "";
	char *temp_ptr = NULL;

	GVariant *params = NULL;
	GVariantBuilder *builder;
	GVariant *message = NULL;

	if (prof_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

#if defined TIZEN_DUALSIM_ENABLE
	if (prof_info->ProfileInfo.Pdp.PSModemPath[0] != '/' ||
		(g_str_has_suffix(prof_info->ProfileInfo.Pdp.PSModemPath, "0") != TRUE &&
		g_str_has_suffix(prof_info->ProfileInfo.Pdp.PSModemPath, "1") != TRUE)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid modem path: %s",
						prof_info->ProfileInfo.Pdp.PSModemPath);

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}
#endif

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{ss}"));

	g_snprintf(buff_svc_type, 10, "%d", prof_info->ProfileInfo.Pdp.ServiceType);
	temp_ptr = buff_svc_type;

	g_variant_builder_add(builder, "{ss}", service_type, temp_ptr);

	if (strlen(prof_info->ProfileInfo.Pdp.HomeURL) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.HomeURL;

		g_variant_builder_add(builder, "{ss}", home_url, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.net_info.ProxyAddr) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.net_info.ProxyAddr;

		g_variant_builder_add(builder, "{ss}", proxy_addr, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.Password) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.Password;

		g_variant_builder_add(builder, "{ss}", auth_pwd, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.UserName) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.UserName;

		g_variant_builder_add(builder, "{ss}", auth_id, temp_ptr);
	}

	if (prof_info->ProfileInfo.Pdp.AuthInfo.AuthType >= NET_PDP_AUTH_NONE &&
			prof_info->ProfileInfo.Pdp.AuthInfo.AuthType <= NET_PDP_AUTH_CHAP) {
		g_snprintf(buff_auth_type, 10, "%d",
				prof_info->ProfileInfo.Pdp.AuthInfo.AuthType);

		temp_ptr = buff_auth_type;

		g_variant_builder_add(builder, "{ss}", auth_type, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Apn) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Apn;

		g_variant_builder_add(builder, "{ss}", apn, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Keyword) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Keyword;

		g_variant_builder_add(builder, "{ss}", keyword, temp_ptr);
	}

	params = g_variant_new("(@a{ss})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	message = _net_invoke_dbus_method(TELEPHONY_SERVICE,
			prof_info->ProfileInfo.Pdp.PSModemPath,
			TELEPHONY_MODEM_INTERFACE, "AddProfile", params,
			&Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to Add Profile");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	/** Check Reply */
	int add_result = 0;

	g_variant_get(message, "(b)", &add_result);
	if (add_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_reset_pdp_profile(int type, const char * modem_path)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	GVariant *params = NULL;

	params = g_variant_new("(i)", type);

	if (modem_path) {
	Error = _net_invoke_dbus_method_nonblock(TELEPHONY_SERVICE,
				modem_path,
				TELEPHONY_MODEM_INTERFACE,
				"ResetProfile",
				params,
				DBUS_REPLY_TIMEOUT,
				__net_reset_cellular_reply);
	} else {
		Error = _net_invoke_dbus_method_nonblock(TELEPHONY_SERVICE,
				TELEPHONY_MASTER_PATH,
				TELEPHONY_MODEM_INTERFACE,
				"ResetProfile",
				params,
				DBUS_REPLY_TIMEOUT,
				__net_reset_cellular_reply);
	}

	__NETWORK_FUNC_EXIT__;
	return Error;

}

int _net_dbus_modify_pdp_profile(net_profile_info_t *prof_info, const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	const char *service_type = "svc_ctg_id";
	const char *home_url = "home_url";
	const char *proxy_addr = "proxy_addr";
	const char *auth_pwd = "auth_pwd";
	const char *auth_type = "auth_type";
	const char *auth_id = "auth_id";
	const char *apn = "apn";
	const char *keyword = "keyword";
	const char *default_conn = "default_internet_conn";
	const char *hidden = "hidden";
	const char *editable = "editable";

	char buff_svc_type[10] = "";
	char buff_auth_type[10] = "";
	char *temp_ptr = NULL;

	GVariant *params = NULL;
	GVariantBuilder *builder;
	GVariant *message = NULL;

	if ((prof_info == NULL) || (profile_name == NULL)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid argument");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{ss}"));


	g_snprintf(buff_svc_type, 10, "%d", prof_info->ProfileInfo.Pdp.ServiceType);
	temp_ptr = buff_svc_type;

	g_variant_builder_add(builder, "{ss}", service_type, temp_ptr);

	if (strlen(prof_info->ProfileInfo.Pdp.HomeURL) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.HomeURL;

		g_variant_builder_add(builder, "{ss}", home_url, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.net_info.ProxyAddr) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.net_info.ProxyAddr;

		g_variant_builder_add(builder, "{ss}", proxy_addr, temp_ptr);
	} else
		g_variant_builder_add(builder, "{ss}", proxy_addr, "");

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.Password) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.Password;

		g_variant_builder_add(builder, "{ss}", auth_pwd, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.AuthInfo.UserName) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.AuthInfo.UserName;

		g_variant_builder_add(builder, "{ss}", auth_id, temp_ptr);
	}

	if (prof_info->ProfileInfo.Pdp.AuthInfo.AuthType >= NET_PDP_AUTH_NONE &&
	    prof_info->ProfileInfo.Pdp.AuthInfo.AuthType <= NET_PDP_AUTH_CHAP) {
		g_snprintf(buff_auth_type, 10, "%d",
				prof_info->ProfileInfo.Pdp.AuthInfo.AuthType);
		temp_ptr = buff_auth_type;

		g_variant_builder_add(builder, "{ss}", auth_type, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Apn) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Apn;

		g_variant_builder_add(builder, "{ss}", apn, temp_ptr);
	}

	if (strlen(prof_info->ProfileInfo.Pdp.Keyword) > 0) {
		temp_ptr = prof_info->ProfileInfo.Pdp.Keyword;

		g_variant_builder_add(builder, "{ss}", keyword, temp_ptr);
	}

	if (prof_info->ProfileInfo.Pdp.Hidden)
		temp_ptr = "TRUE";
	else
		temp_ptr = "FALSE";

	g_variant_builder_add(builder, "{ss}", hidden, temp_ptr);

	if (prof_info->ProfileInfo.Pdp.Editable)
		temp_ptr = "TRUE";
	else
		temp_ptr = "FALSE";

	g_variant_builder_add(builder, "{ss}", editable, temp_ptr);

	if (prof_info->ProfileInfo.Pdp.DefaultConn)
		temp_ptr = "TRUE";
	else
		temp_ptr = "FALSE";

	g_variant_builder_add(builder, "{ss}", default_conn, temp_ptr);

	params = g_variant_new("(@a{ss})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	message = _net_invoke_dbus_method(TELEPHONY_SERVICE, profile_name,
			TELEPHONY_PROFILE_INTERFACE, "ModifyProfile", params,
			&Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to Modify Profile");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	/** Check Reply */
	int add_result = 0;
	g_variant_get(message, "(b)", &add_result);
	NETWORK_LOG(NETWORK_HIGH, "Profile modify result: %d", add_result);

	if (add_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_load_wifi_driver(gboolean wifi_picker_test)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *params;

	params = g_variant_new("(b)", wifi_picker_test);

	/* use DBus signal than reply pending because of performance reason */
	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"LoadDriver", params, DBUS_REPLY_TIMEOUT,
			__net_wifi_power_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_remove_wifi_driver(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	/* use DBus signal than reply pending because of performance reason */
	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"RemoveDriver", NULL, DBUS_REPLY_TIMEOUT,
			__net_wifi_power_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_specific_scan_request(const char *ssid)
{
	__NETWORK_FUNC_ENTER__;

	GVariant *params = NULL;
	net_err_t Error = NET_ERR_NONE;

	params = g_variant_new("(s)", ssid);

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"RequestSpecificScan", params, 6 * DBUS_REPLY_TIMEOUT,
			__net_specific_scan_wifi_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_wps_scan_request(void)
{
	__NETWORK_FUNC_ENTER__;
	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"RequestWpsScan", NULL, 6 * DBUS_REPLY_TIMEOUT,
			__net_wps_scan_wifi_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_get_passpoint(int *enabled)
{
	__NETWORK_FUNC_ENTER__;

	GVariant *message = NULL;
	net_err_t Error = NET_ERR_NONE;

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"GetPasspoint", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to Get Passpoint");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	/** Check Reply */
	int result = 0;
	g_variant_get(message, "(i)", &result);
	*enabled = result;

	NETWORK_LOG(NETWORK_HIGH, "Get passpoint result: %d", result);

	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_passpoint(int enable)
{
	__NETWORK_FUNC_ENTER__;

	GVariant *params;
	net_err_t Error = NET_ERR_NONE;

	params = g_variant_new("(i)", enable);

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
			"SetPasspoint", params, 6 * DBUS_REPLY_TIMEOUT,
			__net_set_passpoint_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

#if defined TIZEN_TV
static void __net_wps_cancel_reply(GObject *source_object,
		GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	NETWORK_LOG(NETWORK_LOW, "__net_wps_cancel_wifi_reply() called\n");

	GDBusConnection *conn = NULL;
	GVariant *dbus_result = NULL;
	GError *error = NULL;

	conn = G_DBUS_CONNECTION(source_object);
	dbus_result = g_dbus_connection_call_finish(conn, res, &error);

	if (error != NULL) {
		NETWORK_LOG(NETWORK_ERROR, "error msg - [%s]\n", error->message);
		g_error_free(error);
	}

	if (dbus_result)
		g_variant_unref(dbus_result);

	_net_dbus_pending_call_unref();

	__NETWORK_FUNC_EXIT__;
}


int _net_dbus_cancel_wps(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_TV_PROFILE_INTERFACE,
			"RequestWpsCancel", NULL, DBUS_REPLY_TIMEOUT,
			__net_wps_cancel_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;

}

static int __net_dbus_set_agent_field(const char *key, const char *value)
{
	__NETWORK_FUNC_ENTER__;

	GVariant *params = NULL;
	GVariantBuilder *builder;
	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	char path[CONNMAN_MAX_BUFLEN] = NETCONFIG_WIFI_PATH;

	builder = g_variant_builder_new(G_VARIANT_TYPE("a{ss}"));
	g_variant_builder_add(builder, "{ss}", key, value);

	params = g_variant_new("(@a{ss})", g_variant_builder_end(builder));
	g_variant_builder_unref(builder);

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, path,
			CONNMAN_AGENT_INTERFACE, "SetField", params, &Error);

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "_net_invoke_dbus_method failed");

	if (message != NULL)
		g_variant_unref(message);
	else
		 NETWORK_LOG(NETWORK_ERROR, "Failed to set agent field");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static void __net_wps_connect_wifi_reply(GObject *source_object,
						GAsyncResult *res, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	int callback_flag = FALSE;
	GDBusConnection *conn = NULL;
	GError *error = NULL;
	GVariant *dbus_result = NULL;
	net_event_info_t event_data;
	net_err_t Error = NET_ERR_NONE;
	network_request_table_t *wps_info =
			&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS];
	memset(&event_data, 0, sizeof(event_data));

	conn = G_DBUS_CONNECTION(source_object);
	dbus_result = g_dbus_connection_call_finish(conn, res, &error);

	if (error != NULL) {
		NETWORK_LOG(NETWORK_HIGH, "error msg - [%s]\n", error->message);
		Error = __net_error_string_to_enum(error->message);
		g_error_free(error);
	} else
		NETWORK_LOG(NETWORK_LOW, "error msg is NULL\n");

	if (dbus_result)
		g_variant_unref(dbus_result);

	if (Error == NET_ERR_NONE)
		goto done;

	NETWORK_LOG(NETWORK_ERROR, "Connection open failed. Error [%d]\n", Error);

	memset(wps_info, 0, sizeof(network_request_table_t));

	event_data.Error = Error;
	event_data.Event = NET_EVENT_WIFI_WPS_RSP;

	NETWORK_LOG(NETWORK_HIGH, "Sending NET_EVENT_WIFI_WPS_RSP Error = %s\n",
			_net_print_error(event_data.Error));

	callback_flag = TRUE;

done:
	_net_dbus_pending_call_unref();

	if (callback_flag)
		_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

int _net_dbus_open_connection_without_ssid()
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *params = NULL;

	params = g_variant_new("(s)", "PBC");
	NETWORK_LOG(NETWORK_ERROR, "Invoke wps connection without ssid");

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_TV_PROFILE_INTERFACE,
			"RequestWpsConnect", params, DBUS_REPLY_TIMEOUT,
			__net_wps_connect_wifi_reply);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_dbus_open_pin_connection_without_ssid(const char *pin)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	GVariant *params = NULL;
	params = g_variant_new("(s)", pin);

	Error = _net_invoke_dbus_method_nonblock(NETCONFIG_SERVICE,
			NETCONFIG_WIFI_PATH, NETCONFIG_TV_PROFILE_INTERFACE,
			"RequestWpsConnect", params, DBUS_REPLY_TIMEOUT,
			__net_wps_connect_wifi_reply);


	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_dbus_set_agent_wps_pbc(void)
{
	__NETWORK_FUNC_ENTER__;

	int ret_val;

	ret_val = __net_dbus_set_agent_field(NETCONFIG_AGENT_FIELD_WPS_PBC, "enable");
	if (NET_ERR_NONE != ret_val) {
		NETWORK_LOG(NETWORK_ERROR, "__net_dbus_set_agent_field failed. Error = %d \n", ret_val);
		return ret_val;
	}

	NETWORK_LOG(NETWORK_HIGH, "Successfully sent wps pbc\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_dbus_set_agent_wps_pin(const char *wps_pin)
{
	__NETWORK_FUNC_ENTER__;

	int ret_val;

	if (NULL == wps_pin || strlen(wps_pin) <= 0) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid param \n");
		return NET_ERR_INVALID_PARAM;
	}

	ret_val = __net_dbus_set_agent_field(NETCONFIG_AGENT_FIELD_WPS_PIN, wps_pin);
	if (NET_ERR_NONE != ret_val) {
		NETWORK_LOG(NETWORK_ERROR, "__net_dbus_set_agent_field failed. Error = %d \n", ret_val);
		return ret_val;
	}

	NETWORK_LOG(NETWORK_HIGH, "Successfully sent wps pin\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}
#endif

int _net_dbus_tdls_disconnect(const char* peer_mac_addr)
{

	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	GVariant *params = NULL;
	const char *method = "TdlsDisconnect";
	gint32 ret = -1;

	params = g_variant_new("(s)", peer_mac_addr);

	message = _net_invoke_dbus_method(
			NETCONFIG_SERVICE, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, method, params, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to TDLS Disconnect Request\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(message, "(i)", &ret);

	NETWORK_LOG(NETWORK_HIGH, "Status [%d]\n", ret);

	if (ret)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);
	__NETWORK_FUNC_EXIT__;

	return Error;
}

int _net_dbus_tdls_connected_peer(char** peer_mac_addr)
{

	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	const char *method = "TdlsConnectedPeer";


	if (NULL == peer_mac_addr) {
			NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_INVALID_PARAM;
	}

	message = _net_invoke_dbus_method(
			NETCONFIG_SERVICE, NETCONFIG_WIFI_PATH,
			NETCONFIG_WIFI_INTERFACE, method, NULL, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to Get Peer Connected Mac address\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(message, "(s)", peer_mac_addr);

	NETWORK_LOG(NETWORK_HIGH, "TDLS Peer Mac address [%s]\n", *peer_mac_addr);

	g_variant_unref(message);
	__NETWORK_FUNC_EXIT__;

	return Error;
}
