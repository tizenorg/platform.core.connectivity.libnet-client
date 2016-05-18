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

#include "network-internal.h"
#include "network-dbus-request.h"
#include "network-signal-handler.h"

extern __thread network_info_t NetworkInfo;
extern __thread network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

static __thread net_state_type_t service_state_table[NET_DEVICE_MAX] = {
							NET_STATE_TYPE_UNKNOWN, };
static __thread int net_service_error = NET_ERR_NONE;
static __thread guint gdbus_conn_subscribe_id_connman_state = 0;
static __thread guint gdbus_conn_subscribe_id_connman_error = 0;
static __thread guint gdbus_conn_subscribe_id_supplicant = 0;
static __thread guint gdbus_conn_subscribe_id_netconfig_wifi = 0;
static __thread guint gdbus_conn_subscribe_id_netconfig = 0;

static int __net_handle_wifi_power_rsp(gboolean value)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = { 0, };

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
		NETWORK_LOG(NETWORK_LOW, "NET_EVENT_WIFI_POWER_RSP wifi state: %d",
				NetworkInfo.wifi_state);

		_net_dbus_pending_call_unref();
	} else {
		event_data.Event = NET_EVENT_WIFI_POWER_IND;
		NETWORK_LOG(NETWORK_LOW, "NET_EVENT_WIFI_POWER_IND wifi state: %d",
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

	int count = 0;;
	net_event_info_t event_data = { 0, };

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN],
				0, sizeof(network_request_table_t));

		_net_dbus_pending_call_unref();

		count = (int)g_slist_length(bss_info_list);
		NETWORK_LOG(NETWORK_LOW,
				"Received the signal: %s with total bss count = %d",
				NETCONFIG_SIGNAL_SPECIFIC_SCAN_DONE,
				count);

		event_data.Event = NET_EVENT_SPECIFIC_SCAN_IND;
		event_data.Datalength = count;
		event_data.Data = bss_info_list;

		_net_client_callback(&event_data);
	} else
		g_slist_free_full(bss_info_list, g_free);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_wifi_specific_scan_rsp(GVariant *param)
{
	GVariantIter *iter = NULL;
	GVariant *value = NULL;
	gchar *key = NULL;
	const gchar *ssid = NULL;
	gint32 security = 0;
	gboolean wps = FALSE;
	GSList *bss_info_list = NULL;
	gboolean ssid_found = FALSE;
	gboolean sec_found = FALSE;
	gboolean wps_found = FALSE;

	g_variant_get(param, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "ssid") == 0 && ssid_found == FALSE) {
			ssid = g_variant_get_string(value, NULL);
			NETWORK_LOG(NETWORK_LOW, "SSID: %s", ssid);
			ssid_found = TRUE;
		}
		if (g_strcmp0(key, "security") == 0 && sec_found == FALSE) {
			security = g_variant_get_int32(value);
			NETWORK_LOG(NETWORK_LOW, "with security: %d", security);
			sec_found = TRUE;
		}
		if (g_strcmp0(key, "wps") == 0 && wps_found == FALSE) {
			wps = g_variant_get_boolean(value);
			NETWORK_LOG(NETWORK_LOW, "wps supported: %d", wps);
			wps_found = TRUE;
		}

		if (ssid_found == TRUE && sec_found == TRUE && wps_found == TRUE) {
			struct ssid_scan_bss_info_t *bss = NULL;
			bss = g_try_new0(struct ssid_scan_bss_info_t, 1);
			if (bss == NULL) {
				NETWORK_LOG(NETWORK_ERROR, "Memory allocation error");

				g_slist_free_full(bss_info_list, g_free);
				g_variant_unref(value);
				g_free(key);
				return NET_ERR_UNKNOWN;
			}

			g_strlcpy(bss->ssid, ssid, NET_WLAN_ESSID_LEN);
			bss->security = __net_get_wlan_sec_mode(security);
			bss->wps = (char)wps;
			bss_info_list = g_slist_append(bss_info_list, bss);

			ssid_found = sec_found = wps_found = FALSE;
		}
	}
	g_variant_iter_free(iter);

	__net_handle_specific_scan_resp(bss_info_list);

	/* To enhance performance,
	 * BSS list should be release in a delayed manner in _net_client_callback */

	return NET_ERR_NONE;
}

static int __net_handle_wps_scan_resp(GSList *bss_info_list)
{
	__NETWORK_FUNC_ENTER__;

	int count = 0;;
	net_event_info_t event_data = { 0, };

	if (request_table[NETWORK_REQUEST_TYPE_WPS_SCAN].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_WPS_SCAN],
				0, sizeof(network_request_table_t));

		_net_dbus_pending_call_unref();

		count = (int)g_slist_length(bss_info_list);
		NETWORK_LOG(NETWORK_LOW,
				"Received the signal: %s with total bss count = %d",
				NETCONFIG_SIGNAL_WPS_SCAN_DONE,
				count);

		event_data.Event = NET_EVENT_WPS_SCAN_IND;
		event_data.Datalength = count;
		event_data.Data = bss_info_list;

		_net_client_callback(&event_data);
	} else
		g_slist_free_full(bss_info_list, g_free);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_wifi_wps_scan_rsp(GVariant *param)
{
	GVariantIter *iter = NULL;
	GVariant *value = NULL;
	gchar *key = NULL;
	GSList *bss_info_list = NULL;
	const gchar *ssid = NULL;
	const gchar *bssid = NULL;
	gsize ssid_len;
	int rssi = -89;
	int mode = 0;
	gboolean ssid_found = FALSE;
	gboolean bssid_found = FALSE;
	gboolean rssi_found = FALSE;
	gboolean mode_found = FALSE;

	g_variant_get(param, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "ssid") == 0) {
			ssid = g_variant_get_fixed_array(value, &ssid_len, sizeof(guchar));
			ssid_found = TRUE;
		} else if (g_strcmp0(key, "bssid") == 0) {
			bssid = g_variant_get_string(value, NULL);
			bssid_found = TRUE;
		} else if (g_strcmp0(key, "rssi") == 0) {
			rssi = g_variant_get_int32(value);
			rssi_found = TRUE;
		} else if (g_strcmp0(key, "mode") == 0) {
			mode = g_variant_get_int32(value);
			mode_found = TRUE;
		}

		if (ssid_found == TRUE && bssid_found == TRUE &&
			rssi_found == TRUE && mode_found == TRUE) {
			struct wps_scan_bss_info_t *bss = NULL;
			bss = g_try_new0(struct wps_scan_bss_info_t, 1);
			if (bss == NULL) {
				NETWORK_LOG(NETWORK_ERROR, "Memory allocation error");

				g_slist_free_full(bss_info_list, g_free);
				g_variant_unref(value);
				g_free(key);
				return NET_ERR_UNKNOWN;
			}

			memcpy(bss->ssid, ssid, ssid_len);
			g_strlcpy(bss->bssid, bssid, NET_WLAN_BSSID_LEN+1);
			bss->rssi = rssi;
			bss->mode = mode;
			bss_info_list = g_slist_append(bss_info_list, bss);

			ssid_found = bssid_found = FALSE;
			rssi_found = mode_found = FALSE;
		}
	}
	g_variant_iter_free(iter);

	__net_handle_wps_scan_resp(bss_info_list);

	return NET_ERR_NONE;
}

static void __net_handle_state_ind(const char *profile_name,
		net_state_type_t profile_state)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = { 0, };

	event_data.Error = NET_ERR_NONE;
	event_data.Event = NET_EVENT_NET_STATE_IND;

	g_strlcpy(event_data.ProfileName, profile_name, sizeof(event_data.ProfileName));

	event_data.Datalength = sizeof(net_state_type_t);
	event_data.Data = &profile_state;

	NETWORK_LOG(NETWORK_LOW,
			"Sending NET_EVENT_NET_STATE_IND, state: %d, profile name: %s",
			profile_state, event_data.ProfileName);

	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

static void __net_handle_failure_ind(const char *profile_name,
		net_device_t device_type)
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

		memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION], 0,
						sizeof(network_request_table_t));

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

	if (net_service_error != NET_ERR_NONE)
		event_data.Error = net_service_error;
	else {
		event_data.Error = NET_ERR_CONNECTION_CONNECT_FAILED;
		NETWORK_LOG(NETWORK_ERROR, "Event error defined %d", event_data.Error);
	}
	event_data.Datalength = 0;
	event_data.Data = NULL;

	net_service_error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_ERROR, "State failure %d", event_data.Error);
	_net_client_callback(&event_data);

	/* Reseting the state back in case of failure state */
	service_state_table[device_type] = NET_STATE_TYPE_IDLE;

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

	NETWORK_LOG(NETWORK_LOW, "[%s] %s", state, sig_path);

	if (device_type == NET_DEVICE_WIFI && NetworkInfo.wifi_state == WIFI_OFF) {
		NETWORK_LOG(NETWORK_LOW, "Wi-Fi is off");
		return Error;
	}

	old_state = service_state_table[device_type];
	new_state = string2state(state);

	if (old_state == new_state)
		return Error;

	service_state_table[device_type] = new_state;

	switch (new_state) {
	case NET_STATE_TYPE_IDLE:
		if (device_type == NET_DEVICE_WIFI &&
				NetworkInfo.wifi_state == WIFI_CONNECTED) {
			NetworkInfo.wifi_state = WIFI_ON;
		}
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

				NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP");

				_net_dbus_pending_call_unref();
			} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
					g_strcmp0(sig_path, svc_name2) == 0) {
				memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
						sizeof(network_request_table_t));

				event_data.Event = NET_EVENT_WIFI_WPS_RSP;

				NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP");

				_net_dbus_pending_call_unref();
			} else {
				event_data.Event = NET_EVENT_OPEN_IND;

				NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_IND");
			}

			net_profile_info_t prof_info;
			if ((Error = net_get_profile_info(sig_path, &prof_info)) != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "net_get_profile_info() failed [%s]",
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

		if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag != TRUE &&
			request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag != TRUE &&
			request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag != TRUE) {
			/** Send Close Ind */
			event_data.Error = Error;
			event_data.Event =  NET_EVENT_CLOSE_IND;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			event_data.Datalength = 0;
			event_data.Data = NULL;

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_IND");

			_net_client_callback(&event_data);
		}

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

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_OPEN_RSP");

			_net_dbus_pending_call_unref();

			_net_client_callback(&event_data);
		}

		if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
				g_strcmp0(sig_path, svc_name3) == 0) {
			memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
					sizeof(network_request_table_t));

			/** Send WPS Resp */
			event_data.Error = NET_ERR_OPERATION_ABORTED;
			event_data.Event =  NET_EVENT_WIFI_WPS_RSP;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			event_data.Datalength = 0;
			event_data.Data = NULL;

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_WIFI_WPS_RSP");
			_net_dbus_pending_call_unref();

			_net_client_callback(&event_data);
		}

		if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE &&
				g_strcmp0(sig_path, svc_name1) == 0) {
			memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION], 0,
					sizeof(network_request_table_t));

			/** Send Close Resp */
			event_data.Error = Error;
			event_data.Event =  NET_EVENT_CLOSE_RSP;
			g_strlcpy(event_data.ProfileName, sig_path, NET_PROFILE_NAME_LEN_MAX+1);

			event_data.Datalength = 0;
			event_data.Data = NULL;

			NETWORK_LOG(NETWORK_LOW, "Sending NET_EVENT_CLOSE_RSP");

			_net_dbus_pending_call_unref();

			_net_client_callback(&event_data);
		}
		break;
	}
	case NET_STATE_TYPE_FAILURE:
		__net_handle_failure_ind(sig_path, device_type);
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

	NETWORK_LOG(NETWORK_ERROR, "[%s] %s", key, error);

	net_service_error = string2error(error);

	return NET_ERR_NONE;
}

static int __net_handle_scan_done(GVariant *param)
{
	net_event_info_t event_data = { 0, };

	if (request_table[NETWORK_REQUEST_TYPE_SPECIFIC_SCAN].flag == TRUE)
		return NET_ERR_NONE;
	else if (request_table[NETWORK_REQUEST_TYPE_SCAN].flag == TRUE) {
		memset(&request_table[NETWORK_REQUEST_TYPE_SCAN], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_SCAN_RSP;

		_net_dbus_pending_call_unref();
	} else {
		event_data.Event = NET_EVENT_WIFI_SCAN_IND;
	}

	event_data.Error = NET_ERR_NONE;
	event_data.Datalength = 0;
	event_data.Data = NULL;

	_net_client_callback(&event_data);

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
	if (g_strcmp0(sig_value, "ATTACHED") == 0) {
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
	__NETWORK_FUNC_ENTER__;

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

		g_free((gchar *)value);
		g_free((gchar *)key);
		if (NULL != var)
			g_variant_unref(var);
	}

	__NETWORK_FUNC_EXIT__;
}
static int __net_handle_wifi_tdls_connected_event(GVariant *param)
{
	__NETWORK_FUNC_ENTER__;

	GVariantIter *iter = NULL;
	GVariant *value = NULL;
	const char *key = NULL;
	const gchar *sig_value = NULL;

	g_variant_get(param, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "peermac") == 0) {
			sig_value = g_variant_get_string(value, NULL);

			NETWORK_LOG(NETWORK_ERROR, "TDLS Connected Peer Mac Adress: %s",
						sig_value);
		}
	}
	g_variant_iter_free(iter);

	net_event_info_t event_data;
	memset(&event_data, 0, sizeof(event_data));

	event_data.Error = NET_ERR_NONE;
	event_data.Event = NET_EVENT_TDLS_CONNECTED_IND;
	event_data.Data = g_strdup(sig_value);

	if (event_data.Data)
		event_data.Datalength = strlen(event_data.Data);
	else
		event_data.Datalength = 0;

	NETWORK_LOG(NETWORK_ERROR, "Sending NET_EVENT_TDLS_CONNECTED_IND");
	_net_client_callback(&event_data);
	g_free(event_data.Data);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_wifi_tdls_disconnected_event(GVariant *param)
{
	__NETWORK_FUNC_ENTER__;

	GVariantIter *iter = NULL;
	GVariant *value = NULL;
	const char *key = NULL;
	const gchar *sig_value = NULL;

	g_variant_get(param, "(a{sv})", &iter);

	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "peermac") == 0) {
			sig_value = g_variant_get_string(value, NULL);

			NETWORK_LOG(NETWORK_ERROR, "TDLS Connected Peer Mac Adress: %s",
						sig_value);
		}
	}
	g_variant_iter_free(iter);

	net_event_info_t event_data;
	memset(&event_data, 0, sizeof(event_data));

	event_data.Error = NET_ERR_NONE;
	event_data.Event = NET_EVENT_TDLS_DISCONNECTED_IND;
	event_data.Data = g_strdup(sig_value);

	if (event_data.Data)
		event_data.Datalength = strlen(event_data.Data);
	else
		event_data.Datalength = 0;

	NETWORK_LOG(NETWORK_ERROR, "Sending NET_EVENT_TDLS_DISCONNECTED_IND");
	_net_client_callback(&event_data);
	g_free(event_data.Data);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_handle_wifi_connect_fail_event(GVariant *param)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data = { 0, };
	network_request_table_t *open_info =
			&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION];
	network_request_table_t *wps_info =
			&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS];

	event_data.Datalength = 0;
	event_data.Data = NULL;

	NETWORK_LOG(NETWORK_HIGH, "Failed to connect WiFi");

	if (open_info->flag == TRUE) {
		memset(open_info, 0, sizeof(network_request_table_t));
		event_data.Error = NET_ERR_INVALID_OPERATION;
		event_data.Event = NET_EVENT_OPEN_RSP;
		NETWORK_LOG(NETWORK_HIGH, "Sending NET_EVENT_OPEN_RSP");
	} else if (wps_info->flag == TRUE) {
		memset(wps_info, 0, sizeof(network_request_table_t));
		event_data.Error = NET_ERR_INVALID_OPERATION;
		event_data.Event = NET_EVENT_WIFI_WPS_RSP;
		NETWORK_LOG(NETWORK_HIGH, "Sending NET_EVENT_WIFI_WPS_RSP");
	} else {
		NETWORK_LOG(NETWORK_LOW, "WiFi Connection flag not set");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NONE;
	}
	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static void __net_supplicant_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	if (g_strcmp0(sig, SIGNAL_SCAN_DONE) == 0)
		__net_handle_scan_done(param);
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
	else if (g_strcmp0(sig, NETCONFIG_SIGNAL_WPS_SCAN_DONE) == 0)
		__net_handle_wifi_wps_scan_rsp(param);
	else if (g_strcmp0(sig, NETCONFIG_SIGNAL_TDLS_CONNECTED) == 0)
		__net_handle_wifi_tdls_connected_event(param);
	else if (g_strcmp0(sig, NETCONFIG_SIGNAL_TDLS_DISCONNECTED) == 0)
		__net_handle_wifi_tdls_disconnected_event(param);
	else if (g_strcmp0(sig, NETCONFIG_SIGNAL_WIFI_CONNECT_FAIL) == 0)
		__net_handle_wifi_connect_fail_event(param);
}

static void __net_netconfig_network_signal_filter(GDBusConnection *conn,
		const gchar *name, const gchar *path, const gchar *interface,
		const gchar *sig, GVariant *param, gpointer user_data)
{
	if (g_strcmp0(sig, NETCONFIG_SIGNAL_ETHERNET_CABLE_STATE) == 0)
		__net_handle_ethernet_cable_state_rsp(param);
}

/*****************************************************************************
 * Global Functions
 *****************************************************************************/
int _net_deregister_signal(void)
{
	__NETWORK_FUNC_ENTER__;

	GDBusConnection *connection;
	net_err_t Error = NET_ERR_NONE;

	connection = _net_dbus_get_gdbus_conn();
	if (connection == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Already de-registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	g_dbus_connection_signal_unsubscribe(connection,
						gdbus_conn_subscribe_id_connman_state);
	g_dbus_connection_signal_unsubscribe(connection,
						gdbus_conn_subscribe_id_connman_error);
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

	/* Create supplicant service connection */
	gdbus_conn_subscribe_id_supplicant = g_dbus_connection_signal_subscribe(
			connection,
			SUPPLICANT_SERVICE,
			SUPPLICANT_IFACE_INTERFACE,
			"ScanDone",
			NULL,
			NULL,
			G_DBUS_SIGNAL_FLAGS_NONE,
			__net_supplicant_signal_filter,
			NULL,
			NULL);

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

	if (gdbus_conn_subscribe_id_supplicant == 0 ||
		gdbus_conn_subscribe_id_netconfig_wifi == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Failed register signals "
				"supplicant(%d), netconfig_wifi(%d)",
				gdbus_conn_subscribe_id_supplicant,
				gdbus_conn_subscribe_id_netconfig_wifi);
		Error = NET_ERR_NOT_SUPPORTED;
	}

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

	/* Create connman service state connection */
	gdbus_conn_subscribe_id_connman_state = g_dbus_connection_signal_subscribe(
			connection,
			CONNMAN_SERVICE,
			CONNMAN_SERVICE_INTERFACE,
			SIGNAL_PROPERTY_CHANGED,
			NULL,
			"State",
			G_DBUS_SIGNAL_FLAGS_NONE,
			__net_connman_service_signal_filter,
			NULL,
			NULL);

	/* Create connman service error connection */
	gdbus_conn_subscribe_id_connman_error = g_dbus_connection_signal_subscribe(
			connection,
			CONNMAN_SERVICE,
			CONNMAN_SERVICE_INTERFACE,
			SIGNAL_PROPERTY_CHANGED,
			NULL,
			"Error",
			G_DBUS_SIGNAL_FLAGS_NONE,
			__net_connman_service_signal_filter,
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

	if (gdbus_conn_subscribe_id_connman_state == 0 ||
		gdbus_conn_subscribe_id_connman_error == 0 ||
		gdbus_conn_subscribe_id_netconfig == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Failed register signals "
				"connman_state(%d), connman_error(%d), netconfig(%d)",
				gdbus_conn_subscribe_id_connman_state,
				gdbus_conn_subscribe_id_connman_error,
				gdbus_conn_subscribe_id_netconfig);
		Error = NET_ERR_NOT_SUPPORTED;
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_get_all_tech_states(GVariant *msg, net_state_type_t *state_table)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariantIter *iter_main = NULL;
	GVariantIter *var = NULL;
	GVariant *value = NULL;
	gchar *path = NULL;
	gchar *key = NULL;
	gboolean data;

	g_variant_get(msg, "(a(oa{sv}))", &iter_main);
	while (g_variant_iter_loop(iter_main, "(oa{sv})", &path, &var)) {

		if (path == NULL)
			continue;

		while (g_variant_iter_loop(var, "{sv}", &key, &value)) {
			if (g_strcmp0(key, "Connected") == 0) {
				data = g_variant_get_boolean(value);
				if (!data)
					continue;

				if (g_strcmp0(path, CONNMAN_WIFI_TECHNOLOGY_PREFIX) == 0) {
					*(state_table + NET_DEVICE_WIFI) = NET_STATE_TYPE_READY;
					NetworkInfo.wifi_state = WIFI_CONNECTED;
				} else if (g_strcmp0(path, CONNMAN_CELLULAR_TECHNOLOGY_PREFIX) == 0)
					*(state_table + NET_DEVICE_CELLULAR) = NET_STATE_TYPE_READY;
				else if (g_strcmp0(path, CONNMAN_ETHERNET_TECHNOLOGY_PREFIX) == 0)
					*(state_table + NET_DEVICE_ETHERNET) = NET_STATE_TYPE_READY;
				else if (g_strcmp0(path, CONNMAN_BLUETOOTH_TECHNOLOGY_PREFIX) == 0)
					*(state_table + NET_DEVICE_BLUETOOTH) = NET_STATE_TYPE_READY;
				else
					NETWORK_LOG(NETWORK_ERROR, "Invalid technology type");
			} else if (g_strcmp0(path, CONNMAN_WIFI_TECHNOLOGY_PREFIX) == 0 &&
					g_strcmp0(key, "Powered") == 0) {
				data = g_variant_get_boolean(value);
				if (data == FALSE)
					NetworkInfo.wifi_state = WIFI_OFF;
				else if (data == TRUE && NetworkInfo.wifi_state < WIFI_ON)
					NetworkInfo.wifi_state = WIFI_ON;
			}
		}
	}
	g_variant_iter_free(iter_main);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_dbus_get_all_technology_states(net_state_type_t *state_table)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	message = _net_invoke_dbus_method(CONNMAN_SERVICE,
			CONNMAN_MANAGER_PATH, CONNMAN_MANAGER_INTERFACE,
			"GetTechnologies", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get technology info");
		goto done;
	}

	Error = __net_get_all_tech_states(message, state_table);

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_init_service_state_table(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = __net_dbus_get_all_technology_states(&service_state_table[0]);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "init service state table. "
				"wifi:%d, cellular:%d, ethernet:%d, bluetooth:%d",
				service_state_table[NET_DEVICE_WIFI],
				service_state_table[NET_DEVICE_CELLULAR],
				service_state_table[NET_DEVICE_ETHERNET],
				service_state_table[NET_DEVICE_BLUETOOTH]);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}
