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

#include <dlfcn.h>

#include "network-internal.h"
#include "network-dbus-request.h"

struct gdbus_connection_data {
	GDBusConnection *connection;
	int conn_ref_count;
	GCancellable *cancellable;
	void *handle_libnetwork;
};

struct managed_idle_data {
	GSourceFunc func;
	gpointer user_data;
	guint id;
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
static __thread GSList *managed_idler_list = NULL;

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

static char *__convert_eap_keymgmt_type_to_string(gchar eap_keymgmt)
{
	switch (eap_keymgmt) {
	case WLAN_SEC_EAP_KEYMGMT_FT:
		return "FT";

	case WLAN_SEC_EAP_KEYMGMT_CCKM:
		return "CCKM";

	case WLAN_SEC_EAP_KEYMGMT_OKC:
		return "OKC";

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
	gboolean data;

	if (g_strcmp0(tech_state->technology, "wifi") == 0)
		tech_prefix = CONNMAN_WIFI_TECHNOLOGY_PREFIX;
	else if (g_strcmp0(tech_state->technology, "cellular") == 0)
		tech_prefix = CONNMAN_CELLULAR_TECHNOLOGY_PREFIX;
	else if (g_strcmp0(tech_state->technology, "ethernet") == 0)
		tech_prefix = CONNMAN_ETHERNET_TECHNOLOGY_PREFIX;
	else if (g_strcmp0(tech_state->technology, "bluetooth") == 0)
		tech_prefix = CONNMAN_BLUETOOTH_TECHNOLOGY_PREFIX;
	else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid technology type");
		Error = NET_ERR_INVALID_PARAM;
		goto done;
	}

	g_variant_get(msg, "(a(oa{sv}))", &iter_main);
	while (g_variant_iter_loop(iter_main, "(oa{sv})", &path, &var)) {

		if (path == NULL || g_strcmp0(path, tech_prefix) != 0)
			continue;

		while (g_variant_iter_loop(var, "{sv}", &key, &value)) {
			if (g_strcmp0(key, "Powered") == 0) {
				data = g_variant_get_boolean(value);

				if (data)
					tech_state->Powered = TRUE;
				else
					tech_state->Powered = FALSE;
			} else if (g_strcmp0(key, "Connected") == 0) {
				data = g_variant_get_boolean(value);

				if (data)
					tech_state->Connected = TRUE;
				else
					tech_state->Connected = FALSE;
			} else if (g_strcmp0(key, "Tethering") == 0) {
				/* For further use */
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

	wifi_connection_info.type = "wifi";

	if (wifi_info->wlan_mode == NETPM_WLAN_CONNMODE_ADHOC)
		wifi_connection_info.mode = "adhoc";
	else
		wifi_connection_info.mode = "managed";

	wifi_connection_info.ssid = (char *)wifi_info->essid;

	wifi_connection_info.is_hidden = wifi_info->is_hidden;

	switch (wifi_info->security_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
		wifi_connection_info.security = "none";
		break;

	case WLAN_SEC_MODE_WEP:
		wifi_connection_info.security = "wep";
		wifi_connection_info.passphrase =
				(char *)wifi_info->security_info.authentication.wep.wepKey;
		break;

		/** WPA-PSK(equivalent to WPA-NONE in case of Ad-Hoc) */
	case WLAN_SEC_MODE_WPA_PSK:
		wifi_connection_info.security = "psk";
		wifi_connection_info.passphrase =
				(char *)wifi_info->security_info.authentication.psk.pskKey;
		break;

	/** WPA2-PSK */
	/** WPA-PSK / WPA2-PSK supported */
	case WLAN_SEC_MODE_WPA2_PSK:
		wifi_connection_info.security = "rsn";
		wifi_connection_info.passphrase =
				(char *)wifi_info->security_info.authentication.psk.pskKey;
		break;
	case WLAN_SEC_MODE_WPA_FT_PSK:
		wifi_connection_info.security = "ft_psk";
		wifi_connection_info.passphrase =
				(char *)wifi_info->security_info.authentication.psk.pskKey;
		break;



	case WLAN_SEC_MODE_IEEE8021X:
		wifi_connection_info.security = "ieee8021x";

		wifi_connection_info.eap_type =
				__convert_eap_type_to_string(
						wifi_info->security_info.authentication.eap.eap_type);
		wifi_connection_info.eap_auth =
				__convert_eap_auth_to_string(
						wifi_info->security_info.authentication.eap.eap_auth);
		wifi_connection_info.eap_keymgmt_type =
				__convert_eap_keymgmt_type_to_string(
						wifi_info->security_info.authentication.eap.eap_keymgmt_type);

		if (wifi_info->security_info.authentication.eap.username[0] != '\0')
			wifi_connection_info.identity =
					(char *)wifi_info->security_info.authentication.eap.username;

		if (wifi_info->security_info.authentication.eap.password[0] != '\0')
			wifi_connection_info.password =
					(char *)wifi_info->security_info.authentication.eap.password;

		if (wifi_info->security_info.authentication.eap.ca_cert_filename[0] != '\0')
			wifi_connection_info.ca_cert_file =
					(char *)wifi_info->security_info.authentication.eap.ca_cert_filename;

		if (wifi_info->security_info.authentication.eap.client_cert_filename[0] != '\0')
			wifi_connection_info.client_cert_file =
					(char *)wifi_info->security_info.authentication.eap.client_cert_filename;

		if (wifi_info->security_info.authentication.eap.private_key_filename[0] != '\0')
			wifi_connection_info.private_key_file =
					(char *)wifi_info->security_info.authentication.eap.private_key_filename;

		if (wifi_info->security_info.authentication.eap.private_key_passwd[0] != '\0')
			wifi_connection_info.private_key_password =
					(char *)wifi_info->security_info.authentication.eap.private_key_passwd;
		break;

	default:
		NETWORK_LOG(NETWORK_ERROR, "Invalid security type");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = _net_dbus_connect_service(&wifi_connection_info);
	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "Failed to request connect service. Error [%s]",
				_net_print_error(Error));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static gboolean __net_client_cb_idle(gpointer data)
{
	GSList *bss_info_list = NULL;
	net_event_info_t *event_data = (net_event_info_t *)data;

	if (event_data->Event == NET_EVENT_SPECIFIC_SCAN_IND ||
			event_data->Event == NET_EVENT_WPS_SCAN_IND) {
		bss_info_list = (GSList *)event_data->Data;
	}

	if (NetworkInfo.ClientEventCb != NULL)
		NetworkInfo.ClientEventCb(event_data, NetworkInfo.user_data);

	/* BSS list should be released in a delayed manner */
	if (bss_info_list != NULL)
		g_slist_free_full(bss_info_list, g_free);
	else if (event_data->Datalength > 0)
		g_free(event_data->Data);

	g_free(event_data);

	return FALSE;
}

static gboolean __net_client_cb_conn_idle(gpointer data)
{
	net_event_info_t *event_data = (net_event_info_t *)data;

	if (event_data->Event == NET_EVENT_SPECIFIC_SCAN_IND) {
		/* ClientEventCb only handles NET_EVENT_SPECIFIC_SCAN_IND */
		g_free(event_data);
		return FALSE;
	}

	if (NetworkInfo.ClientEventCb_conn != NULL)
		NetworkInfo.ClientEventCb_conn(event_data, NetworkInfo.user_data_conn);

	if (event_data->Datalength > 0)
		g_free(event_data->Data);

	g_free(event_data);

	return FALSE;
}

static gboolean __net_client_cb_wifi_idle(gpointer data)
{
	net_event_info_t *event_data = (net_event_info_t *)data;

	if (NetworkInfo.ClientEventCb_wifi != NULL)
		NetworkInfo.ClientEventCb_wifi(event_data, NetworkInfo.user_data_wifi);

	if (event_data->Datalength > 0)
		g_free(event_data->Data);

	g_free(event_data);

	return FALSE;
}

void _net_client_callback(net_event_info_t *event_data)
{
	guint id;

	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered. "
				"If multi-threaded, thread integrity be broken.");
		__NETWORK_FUNC_EXIT__;
		return;
	}

	if (NetworkInfo.ClientEventCb != NULL) {
		GSList *bss_info_list = NULL;
		net_event_info_t *client = g_try_new0(net_event_info_t, 1);
		if (client == NULL) {
			__NETWORK_FUNC_EXIT__;
			return;
		}

		memcpy(client, event_data, sizeof(net_event_info_t));

		if (event_data->Event == NET_EVENT_SPECIFIC_SCAN_IND ||
				event_data->Event == NET_EVENT_WPS_SCAN_IND) {
			/* To enhance performance,
			 * BSS list should be delivered directly */
			bss_info_list = (GSList *)event_data->Data;
		} else if (event_data->Datalength > 0) {
			client->Data = g_try_malloc0(event_data->Datalength);
			if (client->Data == NULL) {
				g_free(client);
				__NETWORK_FUNC_EXIT__;
				return;
			}

			memcpy(client->Data, event_data->Data, event_data->Datalength);
		} else {
			client->Datalength = 0;
			client->Data = NULL;
		}

		id = _net_client_callback_add(__net_client_cb_idle, (gpointer)client);
		if (!id) {
			if (bss_info_list != NULL)
				g_slist_free_full(bss_info_list, g_free);
			else if (client->Datalength > 0)
				g_free(client->Data);

			g_free(client);
		}
	}

	if (NetworkInfo.ClientEventCb_conn != NULL &&
			event_data->Event != NET_EVENT_SPECIFIC_SCAN_IND &&
			event_data->Event != NET_EVENT_WPS_SCAN_IND) {
		net_event_info_t *client = g_try_new0(net_event_info_t, 1);
		if (client == NULL) {
			__NETWORK_FUNC_EXIT__;
			return;
		}

		memcpy(client, event_data, sizeof(net_event_info_t));

		if (event_data->Datalength > 0) {
			client->Data = g_try_malloc0(event_data->Datalength);
			if (client->Data == NULL) {
				g_free(client);
				__NETWORK_FUNC_EXIT__;
				return;
			}

			memcpy(client->Data, event_data->Data, event_data->Datalength);
		} else {
			client->Datalength = 0;
			client->Data = NULL;
		}

		id = _net_client_callback_add(__net_client_cb_conn_idle, (gpointer)client);
		if (!id) {
			if (client->Datalength > 0)
				g_free(client->Data);

			g_free(client);
		}
	}

	if (NetworkInfo.ClientEventCb_wifi != NULL) {
		net_event_info_t *client = g_try_new0(net_event_info_t, 1);
		if (client == NULL) {
			__NETWORK_FUNC_EXIT__;
			return;
		}

		memcpy(client, event_data, sizeof(net_event_info_t));
		if (event_data->Datalength > 0) {
			if (event_data->Event == NET_EVENT_SPECIFIC_SCAN_IND ||
				event_data->Event == NET_EVENT_WPS_SCAN_IND) {
				client->Data = g_try_malloc0(sizeof(GSList));
				if (client->Data == NULL) {
					g_free(client);
					__NETWORK_FUNC_EXIT__;
					return;
				}

				memcpy(client->Data, event_data->Data, sizeof(GSList));
			} else {
				client->Data = g_try_malloc0(event_data->Datalength);
				if (client->Data == NULL) {
					g_free(client);
					__NETWORK_FUNC_EXIT__;
					return;
				}

				memcpy(client->Data, event_data->Data, event_data->Datalength);
			}
		} else {
			client->Datalength = 0;
			client->Data = NULL;
		}

		id = _net_client_callback_add(__net_client_cb_wifi_idle, (gpointer)client);
		if (!id) {
			if (client->Datalength > 0)
				g_free(client->Data);

			g_free(client);
		}
	}

	__NETWORK_FUNC_EXIT__;
}

net_wifi_state_t _net_get_wifi_state(net_err_t *net_error)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_tech_state_info_t tech_state = { { 0, }, };
	net_wifi_state_t wifi_state = WIFI_UNKNOWN;

	g_strlcpy(tech_state.technology, "wifi", NET_TECH_LENGTH_MAX);
	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"_net_dbus_get_technology_state() failed. Error [%s]",
			_net_print_error(Error));
		*net_error = Error;
		goto state_done;
	}

	if (tech_state.Powered == TRUE)
		wifi_state = WIFI_ON;
	else
		wifi_state = WIFI_OFF;

state_done:
	__NETWORK_FUNC_EXIT__;
	return wifi_state;
}

static void __net_client_idle_destroy_cb(gpointer data)
{
	__NETWORK_FUNC_ENTER__;

	if (!data) {
		__NETWORK_FUNC_EXIT__;
		return;
	}

	managed_idler_list = g_slist_remove(managed_idler_list, data);
	g_free(data);

	__NETWORK_FUNC_EXIT__;
}

static gboolean __net_client_idle_cb(gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	struct managed_idle_data *data = (struct managed_idle_data *)user_data;

	if (!data) {
		__NETWORK_FUNC_EXIT__;
		return FALSE;
	}

	__NETWORK_FUNC_EXIT__;
	return data->func(data->user_data);
}

guint _net_client_callback_add(GSourceFunc func, gpointer user_data)
{
	__NETWORK_FUNC_ENTER__;

	guint id;
	struct managed_idle_data *data;

	if (!func) {
		__NETWORK_FUNC_EXIT__;
		return 0;
	}

	data = g_try_new0(struct managed_idle_data, 1);
	if (!data) {
		__NETWORK_FUNC_EXIT__;
		return 0;
	}

	data->func = func;
	data->user_data = user_data;

	id = g_idle_add_full(G_PRIORITY_DEFAULT_IDLE, __net_client_idle_cb, data,
			__net_client_idle_destroy_cb);
	if (!id) {
		g_free(data);
		__NETWORK_FUNC_EXIT__;
		return id;
	}

	data->id = id;

	managed_idler_list = g_slist_append(managed_idler_list, data);

	__NETWORK_FUNC_EXIT__;
	return id;
}

void _net_client_callback_cleanup(void)
{
	__NETWORK_FUNC_ENTER__;

	GSList *cur = managed_idler_list;
	GSource *src;
	struct managed_idle_data *data;

	while (cur) {
		GSList *next = cur->next;
		data = (struct managed_idle_data *)cur->data;

		src = g_main_context_find_source_by_id(g_main_context_default(), data->id);
		if (src) {
			g_source_destroy(src);
			cur = managed_idler_list;
		} else
			cur = next;
	}

	g_slist_free(managed_idler_list);
	managed_idler_list = NULL;

	__NETWORK_FUNC_EXIT__;
}

void _net_clear_request_table(void)
{
	__NETWORK_FUNC_ENTER__;

	int i;

	for (i = 0; i < NETWORK_REQUEST_TYPE_MAX; i++)
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
		NETWORK_LOG(NETWORK_ERROR, "A handle of libnetwork is not NULL");

		gdbus_conn.connection = NULL;
	}
}

int _net_dbus_create_gdbus_call(void)
{
	GError *error = NULL;

	if (gdbus_conn.connection != NULL) {
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_ALREADY_REGISTERED;
	}

#if !GLIB_CHECK_VERSION(2,36,0)
	g_type_init();
#endif

	gdbus_conn.connection = g_bus_get_sync(G_BUS_TYPE_SYSTEM, NULL, &error);
	if (gdbus_conn.connection == NULL) {
		if (error != NULL) {
			NETWORK_LOG(NETWORK_ERROR,
					"Failed to connect to the D-BUS daemon [%s]", error->message);
			g_error_free(error);
		}
		return NET_ERR_UNKNOWN;
	}

	gdbus_conn.cancellable = g_cancellable_new();

	if (gdbus_conn.handle_libnetwork != NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"A handle of libnetwork is not NULL and should be released");

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

	if (gdbus_conn.conn_ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "There is no pending call");

		g_object_unref(gdbus_conn.connection);
		gdbus_conn.connection = NULL;
	} else {
		NETWORK_LOG(NETWORK_ERROR,
				"There are %d pending calls, waiting to be cleared",
				gdbus_conn.conn_ref_count);

		if (gdbus_conn.handle_libnetwork != NULL)
			NETWORK_LOG(NETWORK_ERROR, "A handle of libnetwork is not NULL");

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
