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

/*****************************************************************************
 * 	Extern Variables
 *****************************************************************************/
extern __thread network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/
__thread network_info_t NetworkInfo = { 0, };

static int __net_get_default_profile(void *param, net_profile_info_t *active_profile_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (param == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = _net_get_default_profile_info(active_profile_info);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"_net_get_default_profile_info() failed. Error [%s]",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_add_route(const char *ip_addr, const char *interface, int address_family)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	char dest_ip[INET6_ADDRSTRLEN] = { '\0' };
	char netmask[INET_ADDRSTRLEN] = { '\0' };
	char if_name[40] = { '\0' };
	GVariant *params = NULL;

	g_snprintf(dest_ip, INET6_ADDRSTRLEN, "%s", ip_addr);
	g_snprintf(if_name, strlen(interface) + 1, "%s", interface);

	if(address_family == AF_INET) {
		g_snprintf(netmask, INET_ADDRSTRLEN, "255.255.255.255");
		params = g_variant_new("(ssssi)", dest_ip, netmask, if_name, NULL, address_family);
	}

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "AddRoute", params, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to add route\n");
		goto done;
	}

	/** Check Reply */
	gboolean add_result = FALSE;

	g_variant_get(message, "(b)", &add_result);
	NETWORK_LOG(NETWORK_HIGH, "Add route, result : %d\n", add_result);

	if (add_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_remove_route(const char *ip_addr, const char *interface, int address_family)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	char dest_ip[INET6_ADDRSTRLEN] = { '\0' };
	char netmask[INET_ADDRSTRLEN] = { '\0' };
	char if_name[40] = { '\0' };
	GVariant *params = NULL;

	g_snprintf(dest_ip, INET6_ADDRSTRLEN, "%s", ip_addr);
	g_snprintf(if_name, strlen(interface) + 1, "%s", interface);

	if(address_family == AF_INET) {
		g_snprintf(netmask, INET_ADDRSTRLEN, "255.255.255.255");
		params = g_variant_new("(ssssi)", dest_ip, netmask, if_name, NULL, address_family);
	}

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "RemoveRoute", params, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to remove route\n");
		goto done;
	}

	/** Check Reply */
	gboolean remove_result = FALSE;

	g_variant_get(message, "(b)", &remove_result);
	NETWORK_LOG(NETWORK_HIGH, "Remove route, result : %d\n", remove_result);

	if (remove_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_add_route_ipv6(const char *ip_addr, const char *interface, int address_family, const char *gateway)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	char dest_ip[INET6_ADDRSTRLEN] = { '\0' };
	char netmask[INET_ADDRSTRLEN] = { '\0' };
	char if_name[40] = { '\0' };
	GVariant *params = NULL;

	g_snprintf(dest_ip, INET6_ADDRSTRLEN, "%s", ip_addr);
	g_snprintf(if_name, strlen(interface) + 1, "%s", interface);

	if(address_family == AF_INET6) {
		params = g_variant_new("(ssssi)", dest_ip, netmask, if_name, gateway, address_family);
	}

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "AddRoute", params, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to add route\n");
		goto done;
	}

	/** Check Reply */
	gboolean add_result = FALSE;

	g_variant_get(message, "(b)", &add_result);
	NETWORK_LOG(NETWORK_HIGH, "Add route, result : %d\n", add_result);

	if (add_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_remove_route_ipv6(const char *ip_addr, const char *interface, int address_family, const char *gateway)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	char dest_ip[INET6_ADDRSTRLEN] = { '\0' };
	char netmask[INET_ADDRSTRLEN] = { '\0' };
	char if_name[40] = { '\0' };
	GVariant *params = NULL;

	g_snprintf(dest_ip, INET6_ADDRSTRLEN, "%s", ip_addr);
	g_snprintf(if_name, strlen(interface) + 1, "%s", interface);

	if(address_family == AF_INET6)
		params = g_variant_new("(ssssi)", dest_ip, netmask, if_name, gateway, address_family);

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "RemoveRoute", params, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to remove route\n");
		goto done;
	}

	/** Check Reply */
	gboolean remove_result = FALSE;

	g_variant_get(message, "(b)", &remove_result);
	NETWORK_LOG(NETWORK_HIGH, "Remove route, result : %d\n", remove_result);

	if (remove_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_get_netinfo(net_profile_info_t *active_profile_info, net_dev_info_t **net_info)
{
	int Error = NET_ERR_NONE;

	if (active_profile_info->profile_type == NET_DEVICE_CELLULAR)
		*net_info = &active_profile_info->ProfileInfo.Pdp.net_info;
	else if (active_profile_info->profile_type == NET_DEVICE_WIFI)
		*net_info = &active_profile_info->ProfileInfo.Wlan.net_info;
	else if (active_profile_info->profile_type == NET_DEVICE_ETHERNET)
		*net_info = &active_profile_info->ProfileInfo.Ethernet.net_info;
	else if (active_profile_info->profile_type == NET_DEVICE_BLUETOOTH)
		*net_info = &active_profile_info->ProfileInfo.Bluetooth.net_info;
	else
		Error = NET_ERR_UNKNOWN;

	return Error;
}

static gboolean __net_is_connecting(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	char *svc_name1 = request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
	char *svc_name2 = request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
			g_strcmp0(profile_name, svc_name1) == 0) {
		__NETWORK_FUNC_EXIT__;
		return TRUE;
	} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
			g_strcmp0(profile_name, svc_name2) == 0) {
		__NETWORK_FUNC_EXIT__;
		return TRUE;
	}

	__NETWORK_FUNC_EXIT__;
	return FALSE;
}

static void __net_abort_open_connection(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_event_info_t event_data;
	char event_string[64];

	char *svc_name1 = request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName;
	char *svc_name2 = request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].ProfileName;

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE &&
			g_strcmp0(profile_name, svc_name1) == 0) {
		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_OPEN_RSP;
		g_strlcpy(event_string, "Sending NET_EVENT_OPEN_RSP", 64);

		_net_dbus_pending_call_unref();
	} else if (request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS].flag == TRUE &&
			g_strcmp0(profile_name, svc_name2) == 0) {
		memset(&request_table[NETWORK_REQUEST_TYPE_ENROLL_WPS], 0,
				sizeof(network_request_table_t));

		event_data.Event = NET_EVENT_WIFI_WPS_RSP;
		g_strlcpy(event_string, "Sending NET_EVENT_WIFI_WPS_RSP", 64);

		_net_dbus_pending_call_unref();
	} else {
		__NETWORK_FUNC_EXIT__;
		return;
	}

	g_strlcpy(event_data.ProfileName, profile_name, NET_PROFILE_NAME_LEN_MAX+1);
	event_data.Error = NET_ERR_OPERATION_ABORTED;
	event_data.Datalength = 0;
	event_data.Data = NULL;

	NETWORK_LOG(NETWORK_LOW, "%s, Error: %d", event_string, event_data.Error);
	_net_client_callback(&event_data);

	__NETWORK_FUNC_EXIT__;
}

/*****************************************************************************
 * 	ConnMan Client Common Interface API Definition
 *****************************************************************************/
/**
 * @fn  EXPORT_API int net_register_client(net_event_cb_t event_cb, void *user_data)
 *
 * This function registers callback with the network client
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    net_event_cb_t event_cb - Pointer to callback function
 *		 void* user_data - Pointer to user data
 * @param[out]   none
 */
EXPORT_API int net_register_client(net_event_cb_t event_cb, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (event_cb == NULL) {
		 NETWORK_LOG(NETWORK_ERROR, "Invalid EventCb parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ClientEventCb != NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Application already registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_ALREADY_REGISTERED;
	}

	if (NetworkInfo.ref_count < 1) {
		Error = _net_register_signal();
		if (Error != NET_ERR_NONE && Error != NET_ERR_APP_ALREADY_REGISTERED) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to register DBus signal [%s]",
					_net_print_error(Error));
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	if (NetworkInfo.ClientEventCb_wifi == NULL)
		_net_subscribe_signal_wifi();

	NetworkInfo.ClientEventCb = event_cb;
	NetworkInfo.user_data = user_data;

	if (NetworkInfo.ref_count < 1)
		_net_init_service_state_table();

	__sync_fetch_and_add(&NetworkInfo.ref_count, 1);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_register_client_ext(net_event_cb_t event_cb, net_device_t client_type, void *user_data)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (event_cb == NULL ||
			(client_type != NET_DEVICE_DEFAULT &&
			 client_type != NET_DEVICE_WIFI)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid EventCb parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (client_type == NET_DEVICE_DEFAULT) {
		if (NetworkInfo.ClientEventCb_conn != NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Connection CAPI Already registered");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_APP_ALREADY_REGISTERED;
		}
	} else if (client_type == NET_DEVICE_WIFI) {
		if (NetworkInfo.ClientEventCb_wifi != NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi CAPI Already registered");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_APP_ALREADY_REGISTERED;
		}
	}

	if (NetworkInfo.ref_count < 1) {
		Error = _net_register_signal();
		if (Error != NET_ERR_NONE && Error != NET_ERR_APP_ALREADY_REGISTERED) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to register DBus signal [%s]",
					_net_print_error(Error));
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	if (NetworkInfo.ref_count < 1) {
		Error = _net_init_service_state_table();
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to init service state table [%s]",
					_net_print_error(Error));
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	if (client_type == NET_DEVICE_DEFAULT) {
		NetworkInfo.ClientEventCb_conn = event_cb;
		NetworkInfo.user_data_conn = user_data;
	} else if (client_type == NET_DEVICE_WIFI) {
		_net_subscribe_signal_wifi();
		NetworkInfo.ClientEventCb_wifi = event_cb;
		NetworkInfo.user_data_wifi = user_data;
	}

	__sync_fetch_and_add(&NetworkInfo.ref_count, 1);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/**
 * @fn  EXPORT_API int net_deregister_client(void)
 *
 * This function deregisters with network client
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out]   none
 */
EXPORT_API int net_deregister_client(void)
{
	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ref_count < 1 ||
			NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (__sync_sub_and_fetch(&NetworkInfo.ref_count, 1) < 1) {
		_net_deregister_signal();
		_net_clear_request_table();
		_net_client_callback_cleanup();
	}

	NetworkInfo.ClientEventCb = NULL;
	NetworkInfo.user_data = NULL;

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_deregister_client_ext(net_device_t client_type)
{
	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	switch (client_type) {
	case NET_DEVICE_DEFAULT:
		if (NetworkInfo.ClientEventCb_conn == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Connection CAPI was not registered");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_APP_NOT_REGISTERED;
		}
		NetworkInfo.ClientEventCb_conn = NULL;
		NetworkInfo.user_data_conn = NULL;
		break;
	case NET_DEVICE_WIFI:
		if (NetworkInfo.ClientEventCb_wifi == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Wi-Fi CAPI was not registered");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_APP_NOT_REGISTERED;
		}
		NetworkInfo.ClientEventCb_wifi = NULL;
		NetworkInfo.user_data_wifi = NULL;
		break;
	default:
		NETWORK_LOG(NETWORK_ERROR, "Invalid client_type parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (__sync_sub_and_fetch(&NetworkInfo.ref_count, 1) < 1) {
		_net_deregister_signal();
		_net_clear_request_table();
		_net_client_callback_cleanup();
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/**
 * @fn  EXPORT_API int net_get_active_net_info(net_profile_info_t *active_profile_info)
 *
 * This API returns the information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 active_profile_info 	The information of active(default) network profile.
 */
EXPORT_API int net_get_active_net_info(net_profile_info_t *active_profile_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	Error = __net_get_default_profile((void*)active_profile_info, active_profile_info);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_ipaddress(net_addr_t *ip_address)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 ip_address 	Ip address of active(default) network profile.
 */
EXPORT_API int net_get_active_ipaddress(net_addr_t *ip_address)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)ip_address, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		memcpy(ip_address, &net_info->IpAddr, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_ipaddress6(net_addr_t *ip_address)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 ip_address6 	Ip address of active(default) network profile.
 */
EXPORT_API int net_get_active_ipaddress6(net_addr_t *ip_address6)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)ip_address6,
			&active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		memcpy(ip_address6, &net_info->IpAddr6, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_netmask(net_addr_t *netmask)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 netmask 	Netmask of active(default) network profile.
 */
EXPORT_API int net_get_active_netmask(net_addr_t *netmask)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)netmask, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		memcpy(netmask, &net_info->SubnetMask, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_prefixlen6(int *prefixlen6)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return		int	- NET_ERR_NONE on success, negative values for
 * errors
 * @param[in]	none
 * @param[out]	prefixlen6	Prefix Length of IPv6 address of active(default)
 * network profile.
 */
EXPORT_API int net_get_active_prefixlen6(int *prefixlen6)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)prefixlen6,
			&active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		*prefixlen6 = net_info->PrefixLen6;

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_gateway(net_addr_t *gateway)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 gateway 	Gateway address of active(default) network profile.
 */
EXPORT_API int net_get_active_gateway(net_addr_t *gateway)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)gateway, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		memcpy(gateway, &net_info->GatewayAddr, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_gateway6(net_addr_t *gateway6)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 gateway6 	Gateway IPv6 address of active(default) network profile.
 */
EXPORT_API int net_get_active_gateway6(net_addr_t *gateway6)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)gateway6, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		memcpy(gateway6, &net_info->GatewayAddr6, sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_dns(net_addr_t *dns)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 dns 	DNS address of active(default) network profile.
 */
EXPORT_API int net_get_active_dns(net_addr_t *dns)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)dns, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		memcpy(dns, &net_info->DnsAddr[0], sizeof(net_addr_t));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_essid(net_essid_t *essid)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 essid 	ESSID of active(default) network profile.
 */
EXPORT_API int net_get_active_essid(net_essid_t *essid)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_wifi_profile_info_t *wlan_info = NULL;

	Error = __net_get_default_profile((void*)essid, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (active_profile_info.profile_type == NET_DEVICE_CELLULAR) {
		NETWORK_LOG(NETWORK_ERROR, "Active network is cellular type");
		Error = NET_ERR_NO_SERVICE;
	} else if (active_profile_info.profile_type == NET_DEVICE_ETHERNET) {
		NETWORK_LOG(NETWORK_ERROR, "Active network is ethernet type");
		Error = NET_ERR_NO_SERVICE;
	} else if (active_profile_info.profile_type == NET_DEVICE_WIFI) {
		wlan_info = &active_profile_info.ProfileInfo.Wlan;
		memcpy(essid->essid, wlan_info->essid, NET_WLAN_ESSID_LEN+1);
	} else
		Error = NET_ERR_UNKNOWN;

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_get_active_proxy(net_proxy_t *proxy)
 *
 * This API returns a specific information of active(default) network profile.
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    none
 * @param[out] 	 proxy 	Proxy of active(default) network profile.
 */
EXPORT_API int net_get_active_proxy(net_proxy_t *proxy)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t active_profile_info;
	net_dev_info_t *net_info = NULL;

	Error = __net_get_default_profile((void*)proxy, &active_profile_info);
	if (Error != NET_ERR_NONE) {
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_get_netinfo(&active_profile_info, &net_info);

	if (net_info != NULL)
		memcpy(proxy->proxy_addr, net_info->ProxyAddr, NET_PROXY_LEN_MAX+1);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/**
 * @fn  EXPORT_API int net_is_connected(void)
 *
 * This function check's whether connection manager is connected or not
 * This is Sync API.
 *
 * @return       int - TRUE if connected, else FALSE
 * @param[in]    none
 * @param[out]   none
 */
EXPORT_API int net_is_connected(void)
{
	char state[CONNMAN_STATE_STRLEN] = "";
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if ((Error = _net_dbus_get_state(state)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get state. Error [%s]",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return FALSE;
	}

	if ((g_strcmp0(state, "online") == 0) ||
			(g_strcmp0(state, "connected") == 0)) {
		NETWORK_LOG(NETWORK_LOW, "State [%s]", state);

		__NETWORK_FUNC_EXIT__;
		return TRUE;
	}

	__NETWORK_FUNC_EXIT__;
	return FALSE;
}

/**
 * @fn   EXPORT_API int net_get_network_status(net_service_type_t network_type, net_cm_network_status_t* pNetworkStatus)
 *
 * This function requests wifi/pdp network status
 * This is Sync API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    net_service_type_t network_type - Network type (wlan/pdp/default), of whose status to be checked.
 * @param[out]   net_cm_network_status_t* pNetworkStatus - Status of the requested network.
 */

EXPORT_API int net_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status)
{
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if ((Error = _net_dbus_get_network_status(device_type, network_status)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get network status. Error [%s]",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_get_technology_properties(net_device_t tech_type, net_tech_info_t *tech_info)
{
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if ((Error = _net_dbus_get_tech_status(tech_type, tech_info)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get technology status. Error [%s]",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_get_statistics(net_device_t device_type, net_statistics_type_e statistics_type, unsigned long long *size)
{
	net_err_t Error = NET_ERR_NONE;

	if ((Error = _net_dbus_get_statistics(device_type, statistics_type, size)) != NET_ERR_NONE )
		NETWORK_LOG(NETWORK_ERROR, "Failed to get statistics. error: %s",
				_net_print_error(Error));

	return Error;
}

EXPORT_API int net_set_statistics(net_device_t device_type, net_statistics_type_e statistics_type)
{
	net_err_t Error = NET_ERR_NONE;

	if ((Error = _net_dbus_set_statistics(device_type, statistics_type)) != NET_ERR_NONE )
		NETWORK_LOG(NETWORK_ERROR, "Failed to set statistics. error: %s",
				_net_print_error(Error));

	return Error;
}

EXPORT_API int net_add_route(const char *ip_addr, const char *interface, int address_family)
{
	net_err_t Error = NET_ERR_NONE;

	if (ip_addr == NULL || strlen(ip_addr) < 7 || interface == NULL || strlen(interface) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_add_route(ip_addr, interface, address_family);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to add route. Error [%s]",
				_net_print_error(Error));

		return Error;
	}

	return Error;
}

EXPORT_API int net_remove_route(const char *ip_addr, const char *interface, int address_family)
{
	net_err_t Error = NET_ERR_NONE;

	if (ip_addr == NULL || strlen(ip_addr) < 7 || interface == NULL || strlen(interface) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_remove_route(ip_addr, interface, address_family);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to remove route. Error [%s]\n",
				_net_print_error(Error));

		return Error;
	}

	return Error;
}

EXPORT_API int net_add_route_ipv6(const char *ip_addr, const char *interface, int address_family, const char *gateway)
{
	net_err_t Error = NET_ERR_NONE;

	if (ip_addr == NULL || strlen(ip_addr) < 3 || interface == NULL || gateway == NULL || strlen(interface) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_add_route_ipv6(ip_addr, interface, address_family, gateway);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to add route. Error [%s]",
				_net_print_error(Error));

		return Error;
	}

	return Error;
}

EXPORT_API int net_remove_route_ipv6(const char *ip_addr, const char *interface, int address_family, const char *gateway)
{
	net_err_t Error = NET_ERR_NONE;

	if (ip_addr == NULL || strlen(ip_addr) < 3 || interface == NULL || gateway == NULL || strlen(interface) == 0 ) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter\n");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_remove_route_ipv6(ip_addr, interface, address_family, gateway);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to remove route. Error [%s]\n",
				_net_print_error(Error));

		return Error;
	}

	return Error;
}

/**
 * @fn   EXPORT_API int net_get_ethernet_module(int *state)
 *
 * This function is to get ethernet plug in/out state.
 * This is Sync API.
 *
 * @return       0 - on success, negative values for errors
 * @param[in]    int *state - state of ethernet cable
 * @param[out]   none
 */
EXPORT_API int net_get_ethernet_cable_state(int *state)
{
	__NETWORK_FUNC_ENTER__;
	net_err_t Error = NET_ERR_NONE;

	Error = _net_dbus_get_ethernet_cable_state(state);

	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "_net_dbus_get_ethernet_cable_state failed\n");

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Async Function Definition
 *****************************************************************************/
/**
 * @fn   EXPORT_API int net_open_connection_with_profile(const char *profile_name)
 *
 * This function request open connection for the given profile name.
 * This is Async API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    char *ProfileName - Profile Name to be connected
 * @param[out]   none
 */
EXPORT_API int net_open_connection_with_profile(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	NETWORK_LOG(NETWORK_LOW, "Open: %s", profile_name);

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	g_strlcpy(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			profile_name, NET_PROFILE_NAME_LEN_MAX+1);

	Error = _net_dbus_open_connection(profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request open connection, Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
				0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/**
 * @fn   EXPORT_API int net_open_connection_with_preference(net_service_type_t service_type)
 *
 * This function request open connection for the given service type.
 * This is Async API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    net_service_type_t service_type - Service type to be connected
 * @param[out]   none
 */
EXPORT_API int net_open_connection_with_preference(
		net_service_type_t service_type)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t profile_name;
	memset(&profile_name, 0, sizeof(net_profile_name_t));

	if (_net_is_valid_service_type(service_type) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Service Type");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	Error = _net_get_service_profile(service_type, &profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to find service");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	g_strlcpy(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			profile_name.ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	Error = _net_dbus_open_connection(profile_name.ProfileName);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request open connection, Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
				0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

EXPORT_API int net_open_connection_with_preference_ext(net_service_type_t service_type,
		net_profile_name_t *prof_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t profile_name;
	memset(&profile_name, 0, sizeof(net_profile_name_t));

	if (_net_is_valid_service_type(service_type) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid service type");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (prof_name == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "pending call in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_OPERATION;
	}

	Error = _net_get_service_profile(service_type, &profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to find service");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	g_strlcpy(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			profile_name.ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	Error = _net_dbus_open_connection(profile_name.ProfileName);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request open connection, Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
				0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	memcpy(prof_name, &profile_name, sizeof(net_profile_name_t));

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

/**
 * @fn   EXPORT_API int net_close_connection(const char *profile_name)
 *
 * This function requests close connection for the given profile name.
 * This is Async API.
 *
 * @return       int - NET_ERR_NONE on success, negative values for errors
 * @param[in]    char *profile_name - Connected profile Name
 * @param[out]   none
 */
EXPORT_API int net_close_connection(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	gboolean is_connecting = FALSE;

	NETWORK_LOG(NETWORK_LOW, "ProfileName [%s] passed", profile_name);

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid profile name");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Request in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		is_connecting = __net_is_connecting(profile_name);
		if (is_connecting == FALSE) {
			NETWORK_LOG(NETWORK_ERROR, "pending call in progress");

			__NETWORK_FUNC_EXIT__;
			return NET_ERR_IN_PROGRESS;
		}
	}

	request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag = TRUE;
	g_strlcpy(request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].ProfileName,
			profile_name, NET_PROFILE_NAME_LEN_MAX+1);

	Error = _net_dbus_close_connection(profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to request close connection, Error [%s]",
				_net_print_error(Error));

		memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION],
				0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (is_connecting == TRUE)
		__net_abort_open_connection(profile_name);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}
