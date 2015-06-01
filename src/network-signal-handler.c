/*
 * Network Client Library
 *
 * Copyright 2011-2013 Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.1 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://floralicense.org/license/
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

#include "network-internal.h"
#include "network-dbus-request.h"
#include "network-signal-handler.h"

extern __thread network_info_t NetworkInfo;
extern __thread network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

static __thread net_state_type_t service_state_table[NET_DEVICE_MAX] =
						{ NET_STATE_TYPE_UNKNOWN, };
static __thread int net_service_error = NET_ERR_NONE;
static __thread guint gdbus_conn_subscribe_id_connman_svc = 0;
static __thread guint gdbus_conn_subscribe_id_connman_state = 0;
static __thread guint gdbus_conn_subscribe_id_connman_error = 0;
static __thread guint gdbus_conn_subscribe_id_supplicant = 0;
static __thread guint gdbus_conn_subscribe_id_netconfig_wifi = 0;
static __thread guint gdbus_conn_subscribe_id_netconfig = 0;

static int __net_handle_wifi_power_rsp(gboolean value)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = {0,};

	if (value == TRUE) {
		NetworkInfo.wifi_state = WIFI_ON;
		event_data.Error = NET_ERR_NONE;
	} else {
		NetworkInfo.wifi_state = WIFI_OFF;
		event_data.Error = NET_ERR_NONE;

		if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_SCAN],
					0, sizeof(network_request_table_t));
	}

	if (request_table[NETWORK_REQUEST_TYPE_WIFI_POWER].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_WIFI_POWER],
				0, sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_POWER_RSP;
		NETWORK_LOG(NETWORK_LOW, "NET_EVENT_WIFI_POWER_RSP wifi state: %d\n",
				NetworkInfo.wifi_state);

		_net_dbus_pending_call_unref();
	} else {
		event_data.Event = NET_EVENT_WIFI_POWER_IND;
		NETWORK_LOG(NETWORK_LOW, "NET_EVENT_WIFI_POWER_IND wifi state: %d\n",
				NetworkInfo.wifi_state);
	}

	event_data.Datalength = sizeof(net_wifi_state_t);
	event_data.Data = &(NetworkInfo.wifi_state);
	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static wlan_security_mode_type_t __net_get_wlan_sec_mode(int security)
{
	switch (security) {
	default:
		return WLAN_SEC_MODE_NONE;
	case 2:
		return WLAN_SEC_MODE_WEP;
	case 3:
		return WLAN_SEC_MODE_WPA_PSK;
	case 4:
		return WLAN_SEC_MODE_IEEE8021X;
	}
}

static int __net_handle_specific_scan_resp(GSList *bss_info_list)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = {0,};

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN],
				0, sizeof(network_request_table_t));

		_net_dbus_pending_call_unref();

		NETWORK_LOG(NETWORK_LOW,
				"Sending NET_EVENT_SPECIFIC_SCAN_IND"
				"wifi state: %d\n", NetworkInfo.wifi_state);
		NETWORK_LOG(NETWORK_LOW, "bss_info_list: 0x%x\n",
				bss_info_list);

		event_data.Event = NET_EVENT_SPECIFIC_SCAN_IND;
		event_data.Data = bss_info_list;

		_net_client_callback(&event_data);
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_wifi_specific_scan_rsp(GVariant *param)
{
	GVariantIter *iter = NULL;
	GVariant *value = NULL;
	const char *key = NULL;
	const gchar *ssid = NULL;
	gint32 security = 0;
	GSList *bss_info_list = NULL;
	gboolean ssid_found = FALSE;
	gboolean sec_found = FALSE;

	g_variant_get(param, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "ssid") == 0 && ssid_found == FALSE) {
			ssid = g_variant_get_string(value, NULL);
			NETWORK_LOG(NETWORK_LOW, "Got an ssid: %s", ssid);
			ssid_found = TRUE;
		}
		if (g_strcmp0(key, "security") == 0 && sec_found == FALSE) {
			security = g_variant_get_int16(value);
			NETWORK_LOG(NETWORK_LOW, "with security: %d", security);
			sec_found = TRUE;
		}

		if (ssid_found == TRUE && sec_found == TRUE) {
			net_wifi_connection_info_t *resp_data = g_try_new0(
					net_wifi_connection_info_t, 1);
			g_strlcpy(resp_data->essid, ssid, NET_WLAN_ESSID_LEN);
			resp_data->security_info.sec_mode = __net_get_wlan_sec_mode(security);
			bss_info_list = g_slist_append(bss_info_list, resp_data);

			ssid_found = FALSE;
			sec_found = FALSE;
		}
	}
	g_variant_iter_free(iter);

	NETWORK_LOG(NETWORK_LOW,
			"Received the signal: %s with total bss count = %d",
			NETCONFIG_SIGNAL_SPECIFIC_SCAN_DONE,
			g_slist_length(bss_info_list));

	__net_handle_specific_scan_resp(bss_info_list);

	/* Specific Scan response handled. Release/Destroy the list */
	g_slist_free_full(bss_info_list, g_free);

	return NET_ERR_NONE;
}

static void __net_handle_state_ind(const char* profile_name,
		net_state_type_t profile_state)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = {0,};

	event_data.Error = NET_ERR_NONE;
	event_data.Event = NET_EVENT_NET_STATE_IND;

	g_strlcpy(event_data.ProfileName, profile_name,
			sizeof(event_data.ProfileName));

	event_data.Datalength = sizeof(net_state_type_t);
	event_data.Data = &profile_state;

	NETWORK_LOG(NETWORK_LOW,
			"Sending NET_EVENT_NET_STATE_IND, state: %d, profile name: %s\n",
			profile_state, event_data.ProfileName);

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_handle_failure_ind(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = { 0, };

	const char *svc_name1 =
			request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
	const char *svc_name2 =
			request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;
	const char *svc_name3 =
			request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].ProfileName;

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
			strstr(profile_name, svc_name1) != NULL) {
		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_OPEN_RSP;

		_net_dbus_pending_call_unref();
	} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
			g_strcmp0(profile_name, svc_name2) == 0) {
		memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_WPS_RSP;

		_net_dbus_pending_call_unref();
	} else if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE &&
			g_strcmp0(profile_name, svc_name3) == 0) {
		memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_CLOSE_RSP;

		_net_dbus_pending_call_unref();
	} else {
		__net_handle_state_ind(profile_name, NET_STATE_TYPE_FAILURE);

		__NETWORK_FUNC_EXIT__;
		return;
	}

	g_strlcpy(event_data.ProfileName,
			profile_name, NET_PROFILE_NAME_LEN_MAX+1);

	event_data.Error = net_service_error;
	event_data.Datalength = 0;
	event_data.Data = NULL;

	net_service_error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_ERROR, "State failure %d\n", event_data.Error);
	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static int string2state(const char *state)
{
	if (g_strcmp0(state, "idle") == 0)
		return NET_STATE_TYPE_IDLE;
	else if (g_strcmp0(state, "association") == 0)
		return NET_STATE_TYPE_ASSOCIATION;
	else if (g_strcmp0(state, "configuration") == 0)
		return NET_STATE_TYPE_CONFIGURATION;
	else if (g_strcmp0(state, "ready") == 0)
		return NET_STATE_TYPE_READY;
	else if (g_strcmp0(state, "online") == 0)
		return NET_STATE_TYPE_ONLINE;
	else if (g_strcmp0(state, "disconnect") == 0)
		return NET_STATE_TYPE_DISCONNECT;
	else if (g_strcmp0(state, "failure") == 0)
		return NET_STATE_TYPE_FAILURE;

	return NET_STATE_TYPE_UNKNOWN;
}

static int __net_handle_service_state_changed(const gchar *sig_path,
		const char *key, const char *state)
{
	net_err_t Error = NET_ERR_NONE;
	net_state_type_t old_state, new_state;

	net_event_info_t event_data = { 0, };
	net_device_t device_type = NET_DEVICE_UNKNOWN;

	if (sig_path == NULL)
		return Error;

	device_type = _net_get_tech_type_from_path(sig_path);
	if (device_type == NET_DEVICE_UNKNOWN)
		return Error;

	NETWORK_LOG(NETWORK_LOW, "[%s] %s\n", state, sig_path);

	if (device_type == NET_DEVICE_WIFI && NetworkInfo.wifi_state == WIFI_OFF) {
		NETWORK_LOG(NETWORK_LOW, "Wi-Fi is off\n");
		return Error;
	}

	old_state = service_state_table[device_type];
	new_state = string2state(state);

	if (old_state == new_state)
		return Error;

	service_state_table[device_type] = new_state;

	switch (new_state) {
	case NET_STATE_TYPE_IDLE:
	case NET_STATE_TYPE_ASSOCIATION:
	case NET_STATE_TYPE_CONFIGURATION:
		__net_handle_state_ind(sig_path, new_state);
		break;

	case NET_STATE_TYPE_READY:
	case NET_STATE_TYPE_ONLINE:
	{
		if (old_state != NET_STATE_TYPE_READY &&
				old_state != NET_STATE_TYPE_ONLINE) {
			const char *svc_name1 =
					request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
			const char *svc_name2 =
					request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

			if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
					strstr(sig_path, svc_name1) != NULL) {
				memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
						sizeof(network_request_table_t));

				event_data.Event = NET_EVENT_OPEN_RSP;

				NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP\n");

				_net_dbus_pending_call_unref();
			} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
					g_strcmp0(sig_path, svc_name2) == 0) {
				memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
						sizeof(network_request_table_t));

				event_data.Event = NET_EVENT_WIFI_WPS_RSP;

				NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP\n");

				_net_dbus_pending_call_unref();
			} else {
				event_data.Event = NET_EVENT_OPEN_IND;

				NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_IND\n");
			}

			net_profile_info_t prof_info;
			if ((Error = net_get_profile_info(sig_path, &prof_info)) != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "net_get_profile_info() failed [%s]\n",
						_net_print_error(Error));

				event_data.Datalength = 0;
				event_data.Data = NULL;
			} else {
				event_data.Datalength = sizeof(net_profile_info_t);
				event_data.Data = &prof_info;
			}

			event_data.Error = Error;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			_net_client_callback(&event_data);
		} else
			__net_handle_state_ind(sig_path, new_state);

		break;
	}
	case NET_STATE_TYPE_DISCONNECT:
	{
		const char *svc_name1 =
				request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].ProfileName;
		const char *svc_name2 =
				request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
		const char *svc_name3 =
				request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

		if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
				strstr(sig_path, svc_name2) != NULL) {
			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
					sizeof(network_request_table_t));

			/** Send Open Resp */
			event_data.Error = NET_ERR_OPERATION_ABORTED;
			event_data.Event =  NET_EVENT_OPEN_RSP;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			event_data.Datalength = 0;
			event_data.Data = NULL;

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP\n");

			_net_dbus_pending_call_unref();

			_net_client_callback(&event_data);
		} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
				g_strcmp0(sig_path, svc_name3) == 0) {
			memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
					sizeof(network_request_table_t));

			/** Send WPS Resp */
			event_data.Error = NET_ERR_OPERATION_ABORTED;
			event_data.Event =  NET_EVENT_WIFI_WPS_RSP;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			event_data.Datalength = 0;
			event_data.Data = NULL;

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP\n");
			_net_dbus_pending_call_unref();

			_net_client_callback(&event_data);
		} else if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE &&
				g_strcmp0(sig_path, svc_name1) == 0) {
			memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION], 0,
					sizeof(network_request_table_t));

			/** Send Close Resp */
			event_data.Error = Error;
			event_data.Event =  NET_EVENT_CLOSE_RSP;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			event_data.Datalength = 0;
			event_data.Data = NULL;

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_RSP\n");

			_net_dbus_pending_call_unref();

			_net_client_callback(&event_data);
		} else {
			/** Send Close Ind */
			event_data.Error = Error;
			event_data.Event =  NET_EVENT_CLOSE_IND;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			event_data.Datalength = 0;
			event_data.Data = NULL;

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_IND\n");

			_net_client_callback(&event_data);
		}

		break;
	}
	case NET_STATE_TYPE_FAILURE:
		__net_handle_failure_ind(sig_path);
		break;

	default:
		Error = NET_ERR_UNKNOWN_METHOD;
		break;
	}

	return Error;
}

static int string2error(const char *error)
{
	if (g_strcmp0(error, "out-of-range") == 0)
		return NET_ERR_CONNECTION_OUT_OF_RANGE;
	else if (g_strcmp0(error, "pin-missing") == 0)
		return NET_ERR_CONNECTION_PIN_MISSING;
	else if (g_strcmp0(error, "dhcp-failed") == 0)
		return NET_ERR_CONNECTION_DHCP_FAILED;
	else if (g_strcmp0(error, "connect-failed") == 0)
		return NET_ERR_CONNECTION_CONNECT_FAILED;
	else if (g_strcmp0(error, "login-failed") == 0)
		return NET_ERR_CONNECTION_LOGIN_FAILED;
	else if (g_strcmp0(error, "auth-failed") == 0)
		return NET_ERR_CONNECTION_AUTH_FAILED;
	else if (g_strcmp0(error, "invalid-key") == 0)
		return NET_ERR_CONNECTION_INVALID_KEY;

	return NET_ERR_UNKNOWN;
}

static int __net_handle_service_set_error(const char *key, const char *error)
{
	if (error == NULL || *error == '\0')
		return NET_ERR_NONE;

	NETWORK_LOG(NETWORK_LOW, "[%s] %s\n", key, error);

	net_service_error = string2error(error);

	return NET_ERR_NONE;
}

static int __net_handle_scan_done(GVariant *param)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = { 0, };

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		NETWORK_LOG(NETWORK_LOW, "Flag for specific scan is TRUE, so ignore this signal\n");
		return NET_ERR_NONE;
	} else if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SCAN], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_SCAN_RSP;

		_net_dbus_pending_call_unref();

		NETWORK_LOG(NETWORK_LOW, "response ScanDone\n");
	} else {
		event_data.Event = NET_EVENT_WIFI_SCAN_IND;

		NETWORK_LOG(NETWORK_LOW, "indicate ScanDone\n");
	}

	event_data.Error = NET_ERR_NONE;
	event_data.Datalength = 0;
	event_data.Data = NULL;

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_ethernet_cable_state_rsp(GVariant *param)
{
	GVariantIter *iter = NULL;
	GVariant *value = NULL;
	const char *key = NULL;
	const gchar *sig_value = NULL;

	g_variant_get(param, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "key") == 0) {
			sig_value = g_variant_get_string(value, NULL);
			NETWORK_LOG(NETWORK_LOW, "Check Ethernet Monitor Result: %s",
						sig_value);
		}
	}
	g_variant_iter_free(iter);

	net_event_info_t event_data;
	if(g_strcmp0(sig_value, "ATTACHED") == 0) {
			event_data.Event = NET_EVENT_ETHERNET_CABLE_ATTACHED;
			event_data.Error = NET_ERR_NONE;
	} else {
			event_data.Event = NET_EVENT_ETHERNET_CABLE_DETACHED;
			event_data.Error = NET_ERR_NONE;
	}
	event_data.Datalength = 0;
	event_data.Data = NULL;

	_net_client_callback(&event_data);
	return NET_ERR_NONE;
}

static void __net_connman_service_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	const char *key = NULL;
	const char *value = NULL;
	GVariant *var;

	if (g_strcmp0(sig, SIGNAL_PROPERTY_CHANGED) == 0) {
		g_variant_get(param, "(sv)", &key, &var);

		if (g_strcmp0(key, "State") == 0) {
			g_variant_get(var, "s", &value);

			__net_handle_service_state_changed(path, key, value);
		} else if (g_strcmp0(key, "Error") == 0) {
			g_variant_get(var, "s", &value);

			__net_handle_service_set_error(key, value);
		}
	}
}

static void __net_supplicant_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	if (g_strcmp0(sig, SIGNAL_SCAN_DONE) == 0) {
		NETWORK_LOG(NETWORK_HIGH, "ScanDone signal from wpasupplicant\n");
		__net_handle_scan_done(param);
	}
}

static void __net_netconfig_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	if (g_strcmp0(sig, NETCONFIG_SIGNAL_POWERON_COMPLETED) == 0)
		__net_handle_wifi_power_rsp(TRUE);
	else if (g_strcmp0(sig, NETCONFIG_SIGNAL_POWEROFF_COMPLETED) == 0)
		__net_handle_wifi_power_rsp(FALSE);
	else if (g_strcmp0(sig, NETCONFIG_SIGNAL_SPECIFIC_SCAN_DONE) == 0)
		__net_handle_wifi_specific_scan_rsp(param);
}

static void __net_netconfig_network_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	if (g_strcmp0(sig, NETCONFIG_SIGNAL_ETHERNET_CABLE_STATE) == 0)
		__net_handle_ethernet_cable_state_rsp(param);
}

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/
int _net_deregister_signal(void)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *connection;
	net_err_t Error = NET_ERR_NONE;

	connection = _net_dbus_get_gdbus_conn();
	if (connection == NULL) {
		NETWORK_LOG(NETWORK_HIGH, "Already de-registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	g_dbus_connection_signal_unsubscribe(connection,
				gdbus_conn_subscribe_id_connman_svc);
	g_dbus_connection_signal_unsubscribe(connection,
				gdbus_conn_subscribe_id_supplicant);
	g_dbus_connection_signal_unsubscribe(connection,
				gdbus_conn_subscribe_id_netconfig_wifi);
	g_dbus_connection_signal_unsubscribe(connection,
				gdbus_conn_subscribe_id_netconfig);

	Error = _net_dbus_close_gdbus_call();
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_LOW, "Successfully remove signals\n");

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_subscribe_signal_wifi(void)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *connection;
	net_err_t Error = NET_ERR_NONE;

	connection = _net_dbus_get_gdbus_conn();
	if (connection == NULL) {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/* Create net-config service connection */
	gdbus_conn_subscribe_id_netconfig_wifi = g_dbus_connection_signal_subscribe(
						connection,
						NETCONFIG_SERVICE,
						NETCONFIG_WIFI_INTERFACE,
						NULL,
						NETCONFIG_WIFI_PATH,
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						__net_netconfig_signal_filter,
						NULL,
						NULL);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_register_signal(void)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *connection;
	net_err_t Error = NET_ERR_NONE;

	Error = _net_dbus_create_gdbus_call();
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	connection = _net_dbus_get_gdbus_conn();
	if (connection == NULL) {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	/* Create connman service connection */
	gdbus_conn_subscribe_id_connman_svc = g_dbus_connection_signal_subscribe(
						connection,
						CONNMAN_SERVICE,
						CONNMAN_SERVICE_INTERFACE,
						NULL,
						NULL,
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						__net_connman_service_signal_filter,
						NULL,
						NULL);

	/* Create supplicant service connection */
	gdbus_conn_subscribe_id_supplicant = g_dbus_connection_signal_subscribe(
						connection,
						SUPPLICANT_SERVICE,
						SUPPLICANT_SERVICE_INTERFACE,
						NULL,
						NULL,
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						__net_supplicant_signal_filter,
						NULL,
						NULL);

	/* Create net-config service connection */
	gdbus_conn_subscribe_id_netconfig = g_dbus_connection_signal_subscribe(
						connection,
						NETCONFIG_SERVICE,
						NETCONFIG_WIFI_INTERFACE,
						NULL,
						NETCONFIG_WIFI_PATH,
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						__net_netconfig_signal_filter,
						NULL,
						NULL);

	/* Create net-config service connection for network */
	gdbus_conn_subscribe_id_netconfig = g_dbus_connection_signal_subscribe(
						connection,
						NETCONFIG_SERVICE,
						NETCONFIG_NETWORK_INTERFACE,
						NULL,
						NETCONFIG_NETWORK_PATH,
						NULL,
						G_DBUS_SIGNAL_FLAGS_NONE,
						__net_netconfig_network_signal_filter,
						NULL,
						NULL);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_init_service_state_table(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_cm_network_status_t network_status;

	Error = _net_dbus_get_network_status(NET_DEVICE_WIFI, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_WIFI] = NET_STATE_TYPE_READY;

	Error = _net_dbus_get_network_status(NET_DEVICE_CELLULAR, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_CELLULAR] = NET_STATE_TYPE_READY;

	Error = _net_dbus_get_network_status(NET_DEVICE_ETHERNET, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_ETHERNET] = NET_STATE_TYPE_READY;

	Error = _net_dbus_get_network_status(NET_DEVICE_BLUETOOTH, &network_status);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (network_status == NET_STATUS_AVAILABLE)
		service_state_table[NET_DEVICE_BLUETOOTH] = NET_STATE_TYPE_READY;

	NETWORK_LOG(NETWORK_HIGH, "init service state table. "
				"wifi:%d, cellular:%d, ethernet:%d, bluetooth:%d\n",
				service_state_table[NET_DEVICE_WIFI],
				service_state_table[NET_DEVICE_CELLULAR],
				service_state_table[NET_DEVICE_ETHERNET],
				service_state_table[NET_DEVICE_BLUETOOTH]);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}
