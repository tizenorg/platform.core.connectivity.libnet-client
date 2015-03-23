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

#include <dlfcn.h>

#include "network-internal.h"
#include "network-dbus-request.h"

struct gdbus_connection_data {
	GDBusConnection *connection;
	int conn_ref_count;
	GCancellable *cancellable;
	void *handle_libnetwork;
};

/*****************************************************************************
 * 	Extern Global Variables
 *****************************************************************************/
extern __thread network_info_t NetworkInfo;

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/
__thread network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX] = { { 0, }, };

static __thread struct gdbus_connection_data gdbus_conn = { NULL, 0, NULL, NULL };

static char *__convert_eap_type_to_string(gchar eap_type)
{
	switch (eap_type) {
	case WLAN_SEC_EAP_TYPE_PEAP:
		return "peap";

	case WLAN_SEC_EAP_TYPE_TLS:
		return "tls";

	case WLAN_SEC_EAP_TYPE_TTLS:
		return "ttls";

	case WLAN_SEC_EAP_TYPE_SIM:
		return "sim";

	case WLAN_SEC_EAP_TYPE_AKA:
		return "aka";

	default:
		return NULL;
	}
}

static char *__convert_eap_auth_to_string(gchar eap_auth)
{
	switch (eap_auth) {
	case WLAN_SEC_EAP_AUTH_NONE:
		return "NONE";

	case WLAN_SEC_EAP_AUTH_PAP:
		return "PAP";

	case WLAN_SEC_EAP_AUTH_MSCHAP:
		return "MSCHAP";

	case WLAN_SEC_EAP_AUTH_MSCHAPV2:
		return "MSCHAPV2";

	case WLAN_SEC_EAP_AUTH_GTC:
		return "GTC";

	case WLAN_SEC_EAP_AUTH_MD5:
		return "MD5";

	default:
		return NULL;
	}
}

/*****************************************************************************
 * 	Global Functions Definition
 *****************************************************************************/

char* _net_print_error(net_err_t error)
{
	switch (error) {
		/** No error */
	case NET_ERR_NONE:
		return "NET_ERR_NONE";

		/* Common Error value */

		/** Error unknown */
	case NET_ERR_UNKNOWN:
		return "NET_ERR_UNKNOWN";

		/* Client Register related Errors used in API return */

		/** Application is already registered */
	case NET_ERR_APP_ALREADY_REGISTERED:
		return "NET_ERR_APP_ALREADY_REGISTERED";
		/** Application is not registered */
	case NET_ERR_APP_NOT_REGISTERED:
		return "NET_ERR_APP_NOT_REGISTERED";

		/* Connection Related Error */

		/** No active connection exists for the given profile name */
	case NET_ERR_NO_ACTIVE_CONNECTIONS:
		return "NET_ERR_NO_ACTIVE_CONNECTIONS";
		/** Active connection already exists for the given profile name  */
	case NET_ERR_ACTIVE_CONNECTION_EXISTS:
		return "NET_ERR_ACTIVE_CONNECTION_EXISTS";

		/** Connection failure : out of range */
	case NET_ERR_CONNECTION_OUT_OF_RANGE:
		return "NET_ERR_CONNECTION_OUT_OF_RANGE";
		/** Connection failure : pin missing */
	case NET_ERR_CONNECTION_PIN_MISSING:
		return "NET_ERR_CONNECTION_PIN_MISSING";
		/** Connection failure : dhcp failed */
	case NET_ERR_CONNECTION_DHCP_FAILED:
		return "NET_ERR_CONNECTION_DHCP_FAILED";
		/** Connection failure */
	case NET_ERR_CONNECTION_CONNECT_FAILED:
		return "NET_ERR_CONNECTION_CONNECT_FAILED";
		/** Connection failure : login failed */
	case NET_ERR_CONNECTION_LOGIN_FAILED:
		return "NET_ERR_CONNECTION_LOGIN_FAILED";
		/** Connection failure : authentication failed */
	case NET_ERR_CONNECTION_AUTH_FAILED:
		return "NET_ERR_CONNECTION_AUTH_FAILED";
		/** Connection failure : invalid key */
	case NET_ERR_CONNECTION_INVALID_KEY:
		return "NET_ERR_CONNECTION_INVALID_KEY";

		/* Other Error */

		/** Access is denied */
	case NET_ERR_ACCESS_DENIED:
		return "NET_ERR_ACCESS_DENIED";
		/** Operation is in progress */
	case NET_ERR_IN_PROGRESS:
		return "NET_ERR_IN_PROGRESS";
		/** Operation was aborted by client or network*/
	case NET_ERR_OPERATION_ABORTED:
		return "NET_ERR_OPERATION_ABORTED";
		/** Invalid value of API parameter */
	case NET_ERR_INVALID_PARAM:
		return "NET_ERR_INVALID_PARAM";
		/** invalid operation depending on current state */
	case NET_ERR_INVALID_OPERATION:
		return "NET_ERR_INVALID_OPERATION";

		/** Feature not supported */
	case NET_ERR_NOT_SUPPORTED:
		return "NET_ERR_NOT_SUPPORTED";
		/** TimeOut Error */
	case NET_ERR_TIME_OUT:
		return "NET_ERR_TIME_OUT";
		/** Network service is not available*/
	case NET_ERR_NO_SERVICE:
		return "NET_ERR_NO_SERVICE";
		/** DBus can't find appropriate method */
	case NET_ERR_UNKNOWN_METHOD:
		return "NET_ERR_UNKNOWN_METHOD";
		/** Operation is restricted */
	case NET_ERR_SECURITY_RESTRICTED:
		return "NET_ERR_SECURITY_RESTRICTED";
		/** WiFi driver on/off failed */
	case NET_ERR_WIFI_DRIVER_FAILURE:
		return "NET_ERR_WIFI_DRIVER_FAILURE";
	default:
		return "INVALID";
	}
}

int _net_is_valid_service_type(net_service_type_t service_type)
{
	switch (service_type) {
	case NET_SERVICE_INTERNET:
	case NET_SERVICE_MMS:
	case NET_SERVICE_PREPAID_INTERNET:
	case NET_SERVICE_PREPAID_MMS:
	case NET_SERVICE_TETHERING:
	case NET_SERVICE_APPLICATION:
		break;
	default:
		return FALSE;
	}

	return TRUE;
}

net_device_t _net_get_tech_type_from_path(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_device_t device_type = NET_DEVICE_UNKNOWN;

	if (g_str_has_prefix(profile_name,
			CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE)
		device_type = NET_DEVICE_WIFI;
	else if (g_str_has_prefix(profile_name,
			CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX) == TRUE)
		device_type = NET_DEVICE_CELLULAR;
	else if (g_str_has_prefix(profile_name,
			CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX) == TRUE)
		device_type = NET_DEVICE_ETHERNET;
	else if (g_str_has_prefix(profile_name,
			CONNMAN_BLUETOOTH_SERVICE_PROFILE_PREFIX) == TRUE)
		device_type = NET_DEVICE_BLUETOOTH;

	__NETWORK_FUNC_EXIT__;
	return device_type;
}

int _net_get_tech_state(GVariant *msg, network_tech_state_info_t* tech_state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariantIter *iter_main = NULL;
	GVariantIter *var = NULL;
	GVariant *value = NULL;
	gchar *tech_prefix;
	gchar *path = NULL;
	gchar *key = NULL;
	gboolean data = FALSE;

	if (g_str_equal(tech_state->technology, "wifi") == TRUE)
		tech_prefix = CONNMAN_WIFI_TECHNOLOGY_PREFIX;
	else if (g_str_equal(tech_state->technology, "cellular") == TRUE)
		tech_prefix = CONNMAN_CELLULAR_TECHNOLOGY_PREFIX;
	else if (g_str_equal(tech_state->technology, "ethernet") == TRUE)
		tech_prefix = CONNMAN_ETHERNET_TECHNOLOGY_PREFIX;
	else if (g_str_equal(tech_state->technology, "bluetooth") == TRUE)
		tech_prefix = CONNMAN_BLUETOOTH_TECHNOLOGY_PREFIX;
	else {
		NETWORK_LOG(NETWORK_LOW, "Invalid technology type\n");
		Error = NET_ERR_INVALID_PARAM;
		goto done;
	}

	g_variant_get(msg, "(a(oa{sv}))", &iter_main);
	while (g_variant_iter_loop(iter_main, "(oa{sv})", &path, &var)) {

		if (path == NULL || g_str_equal(path, tech_prefix) != TRUE)
			continue;

		NETWORK_LOG(NETWORK_LOW, "Path - [%s]", path);

		while (g_variant_iter_loop(var, "{sv}", &key, &value)) {
			if (g_strcmp0(key, "Powered") == 0) {
				data = g_variant_get_boolean(value);

				if (data)
					tech_state->Powered = TRUE;
				else
					tech_state->Powered = FALSE;

				NETWORK_LOG(NETWORK_ERROR, "key-[%s]-[%d]", key, tech_state->Powered);
			} else if (g_strcmp0(key, "Connected") == 0) {
				data = g_variant_get_boolean(value);

				if (data)
					tech_state->Connected = TRUE;
				else
					tech_state->Connected = FALSE;

				NETWORK_LOG(NETWORK_ERROR, "key-[%s]-[%d]", key, tech_state->Connected);
			} else if (g_strcmp0(key, "Tethering") == 0) {
				data = g_variant_get_boolean(value);
				if (data)
					tech_state->Tethering = TRUE;
				else
					tech_state->Tethering = FALSE;
				NETWORK_LOG(NETWORK_ERROR, "key-[%s]-[%d]", key, tech_state->Tethering);
			}
		}
	}
	g_variant_iter_free(iter_main);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

/** This function is used only to open Wi-Fi connection with hidden APs */
int _net_open_connection_with_wifi_info(const net_wifi_connection_info_t* wifi_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	net_wifi_connect_service_info_t wifi_connection_info;
	memset(&wifi_connection_info, 0, sizeof(net_wifi_connect_service_info_t));

	wifi_connection_info.type = g_strdup("wifi");

	if (wifi_info->wlan_mode == NETPM_WLAN_CONNMODE_ADHOC)
		wifi_connection_info.mode = g_strdup("adhoc");
	else
		wifi_connection_info.mode = g_strdup("managed");

	wifi_connection_info.ssid = g_strdup(wifi_info->essid);

	switch (wifi_info->security_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
		wifi_connection_info.security = g_strdup("none");
		break;

	case WLAN_SEC_MODE_WEP:
		wifi_connection_info.security = g_strdup("wep");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->security_info.authentication.wep.wepKey);
		break;

	/** WPA-PSK(equivalent to WPA-NONE in case of Ad-Hoc) */
	case WLAN_SEC_MODE_WPA_PSK:
		wifi_connection_info.security = g_strdup("psk");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->security_info.authentication.psk.pskKey);
		break;

	/** WPA2-PSK */
	/** WPA-PSK / WPA2-PSK supported */
	case WLAN_SEC_MODE_WPA2_PSK:
		wifi_connection_info.security = g_strdup("rsn");
		wifi_connection_info.passphrase =
				g_strdup(wifi_info->security_info.authentication.psk.pskKey);
		break;

	case WLAN_SEC_MODE_IEEE8021X:
		wifi_connection_info.security = g_strdup("ieee8021x");

		wifi_connection_info.eap_type = g_strdup(
				__convert_eap_type_to_string(
						wifi_info->security_info.authentication.eap.eap_type));
		wifi_connection_info.eap_auth = g_strdup(
				__convert_eap_auth_to_string(
						wifi_info->security_info.authentication.eap.eap_auth));

		if (wifi_info->security_info.authentication.eap.username[0] != '\0')
			wifi_connection_info.identity =
					g_strdup(wifi_info->security_info.authentication.eap.username);

		if (wifi_info->security_info.authentication.eap.password[0] != '\0')
			wifi_connection_info.password =
					g_strdup(wifi_info->security_info.authentication.eap.password);

		if (wifi_info->security_info.authentication.eap.ca_cert_filename[0] != '\0')
			wifi_connection_info.ca_cert_file =
					g_strdup(wifi_info->security_info.authentication.eap.ca_cert_filename);

		if (wifi_info->security_info.authentication.eap.client_cert_filename[0] != '\0')
			wifi_connection_info.client_cert_file =
					g_strdup(wifi_info->security_info.authentication.eap.client_cert_filename);

		if (wifi_info->security_info.authentication.eap.private_key_filename[0] != '\0')
			wifi_connection_info.private_key_file =
					g_strdup(wifi_info->security_info.authentication.eap.private_key_filename);

		if (wifi_info->security_info.authentication.eap.private_key_passwd[0] != '\0')
			wifi_connection_info.private_key_password =
					g_strdup(wifi_info->security_info.authentication.eap.private_key_passwd);

		break;
	default:
		NETWORK_LOG(NETWORK_ERROR, "Invalid security type\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = _net_dbus_connect_service(&wifi_connection_info);
	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "Failed to request connect service. Error [%s]\n",
				_net_print_error(Error));
	else
		NETWORK_LOG(NETWORK_HIGH, "Successfully requested to connect service\n");

	g_free(wifi_connection_info.type);
	g_free(wifi_connection_info.mode);
	g_free(wifi_connection_info.ssid);
	g_free(wifi_connection_info.security);
	g_free(wifi_connection_info.passphrase);
	g_free(wifi_connection_info.eap_type);
	g_free(wifi_connection_info.eap_auth);
	g_free(wifi_connection_info.identity);
	g_free(wifi_connection_info.password);
	g_free(wifi_connection_info.ca_cert_file);
	g_free(wifi_connection_info.client_cert_file);
	g_free(wifi_connection_info.private_key_file);
	g_free(wifi_connection_info.private_key_password);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

void _net_client_callback(net_event_info_t *event_data)
{
	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ClientEventCb != NULL)
		NetworkInfo.ClientEventCb(event_data, NetworkInfo.user_data);

	if (NetworkInfo.ClientEventCb_conn != NULL)
		NetworkInfo.ClientEventCb_conn(event_data, NetworkInfo.user_data_conn);

	if (NetworkInfo.ClientEventCb_wifi != NULL)
		NetworkInfo.ClientEventCb_wifi(event_data, NetworkInfo.user_data_wifi);

	__NETWORK_FUNC_EXIT__;
}

net_wifi_state_t _net_get_wifi_state(void)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_tech_state_info_t tech_state = {{0,},};
	net_wifi_state_t wifi_state = WIFI_UNKNOWN;

	g_strlcpy(tech_state.technology, "wifi", NET_TECH_LENGTH_MAX);
	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"_net_dbus_get_technology_state() failed. Error [%s]\n",
			_net_print_error(Error));
		goto state_done;
	}

	if (tech_state.Powered == TRUE
			&& tech_state.Tethering != TRUE)
		wifi_state = WIFI_ON;
	else
		wifi_state = WIFI_OFF;

state_done:
	__NETWORK_FUNC_EXIT__;
	return wifi_state;
}

void _net_clear_request_table(void)
{
	__NETWORK_FUNC_ENTER__;

	int i = 0;

	for (i = 0;i < NETWORK_REQUEST_TYPE_MAX;i++)
		memset(&request_table[i], 0, sizeof(network_request_table_t));

	__NETWORK_FUNC_EXIT__;
}

gboolean _net_dbus_is_pending_call_used(void)
{
	if (gdbus_conn.conn_ref_count > 0)
		return TRUE;

	return FALSE;
}

void _net_dbus_pending_call_ref(void)
{
	g_object_ref(gdbus_conn.connection);

	__sync_fetch_and_add(&gdbus_conn.conn_ref_count, 1);
}

void _net_dbus_pending_call_unref(void)
{
	if (gdbus_conn.conn_ref_count < 1)
		return;

	g_object_unref(gdbus_conn.connection);

	if (__sync_sub_and_fetch(&gdbus_conn.conn_ref_count, 1) < 1 &&
			gdbus_conn.handle_libnetwork != NULL) {
		NETWORK_LOG(NETWORK_ERROR, "A handle of libnetwork is not NULL\n");

		gdbus_conn.connection = NULL;
	}
}

int _net_dbus_create_gdbus_call(void)
{
	GError *error = NULL;
	gchar *addr;

	if (gdbus_conn.connection != NULL) {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_ALREADY_REGISTERED;
	}

	addr = g_dbus_address_get_for_bus_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (!addr) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to get D-BUS : [%s]\n", error->message);
		g_error_free(error);
		return NET_ERR_UNKNOWN;
	}

	gdbus_conn.connection = g_dbus_connection_new_for_address_sync(addr,
			G_DBUS_CONNECTION_FLAGS_AUTHENTICATION_CLIENT |
			G_DBUS_CONNECTION_FLAGS_MESSAGE_BUS_CONNECTION,
			NULL, NULL, &error);
	g_free(addr);
	if (gdbus_conn.connection == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to connect to the D-BUS daemon: [%s]\n", error->message);
		g_error_free(error);
		return NET_ERR_UNKNOWN;
	}

	gdbus_conn.cancellable = g_cancellable_new();

	if (gdbus_conn.handle_libnetwork != NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"A handle of libnetwork is not NULL and should be released\n");

		dlclose(gdbus_conn.handle_libnetwork);
		gdbus_conn.handle_libnetwork = NULL;
	}

	return NET_ERR_NONE;
}

int _net_dbus_close_gdbus_call(void)
{
	g_cancellable_cancel(gdbus_conn.cancellable);
	g_object_unref(gdbus_conn.cancellable);
	gdbus_conn.cancellable = NULL;

	if (g_dbus_connection_close_sync(gdbus_conn.connection, NULL, NULL) == FALSE) {
		NETWORK_LOG(NETWORK_HIGH, "Failed to close GDBus\n");
		return NET_ERR_UNKNOWN;
	}

	if (gdbus_conn.conn_ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "There is no pending call\n");

		g_object_unref(gdbus_conn.connection);
		gdbus_conn.connection = NULL;
	} else {
		NETWORK_LOG(NETWORK_ERROR,
				"There are %d pending calls, waiting to be cleared\n",
				gdbus_conn.conn_ref_count);

		if (gdbus_conn.handle_libnetwork != NULL)
			NETWORK_LOG(NETWORK_ERROR, "A handle of libnetwork is not NULL\n");

		gdbus_conn.handle_libnetwork =
							dlopen("/usr/lib/libnetwork.so", RTLD_LAZY);

		g_object_unref(gdbus_conn.connection);
	}

	return NET_ERR_NONE;
}

GDBusConnection *_net_dbus_get_gdbus_conn(void)
{
	return gdbus_conn.connection;
}

GCancellable *_net_dbus_get_gdbus_cancellable(void)
{
	return gdbus_conn.cancellable;
}
