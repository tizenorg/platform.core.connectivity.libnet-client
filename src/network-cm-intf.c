/*
 *  Network Client Library
 *
 * Copyright 2011-2013 Samsung Electronics Co., Ltd

 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at

 * http://floralicense.org/license/

 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */


#ifdef __cplusplus
extern "C"
{
#endif /* __cplusplus */


/*****************************************************************************
 * 	Standard headers
 *****************************************************************************/
#include <stdio.h> 
#include <errno.h> 
#include <stdlib.h> 
#include <string.h>
#include <glib.h>

#include <dbus/dbus.h> 


/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

#include "network-internal.h"
#include "network-signal-handler.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/

static int __net_get_default_profile(void *param, net_profile_info_t *active_profile_info);

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

/*****************************************************************************
 * 	Extern Variables
 *****************************************************************************/

extern network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/

network_info_t NetworkInfo = {0, };

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

static int __net_get_default_profile(void *param, net_profile_info_t *active_profile_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (param == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = _net_get_default_profile_info(active_profile_info);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! _net_get_default_profile_info() failed. Error [%s]\n",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_add_route(const char *ip_addr, const char *interface)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessage *message = NULL;
	char dest_ip[30];
	char netmask[30];
	char if_name[40];
	char* param_array[] = { NULL, NULL, NULL, NULL };

	g_snprintf(dest_ip, 30, "string:%s", ip_addr);
	g_snprintf(netmask, 30, "string:255.255.255.255");
	g_snprintf(if_name, 40, "string:%s", interface);

	param_array[0] = dest_ip;
	param_array[1] = netmask;
	param_array[2] = if_name;

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "AddRoute", param_array, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Failed to Add route\n");
		goto done;
	}

	/** Check Reply */
	DBusMessageIter iter;
	int add_result = 0;

	dbus_message_iter_init(message, &iter);
	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_BOOLEAN) {
		dbus_message_iter_get_basic(&iter, &add_result);
		NETWORK_LOG(NETWORK_HIGH, "Add route, result : %d\n", add_result);
	}

	if (add_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	dbus_message_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_remove_route(const char *ip_addr, const char *interface)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessage *message = NULL;
	char dest_ip[30];
	char netmask[30];
	char if_name[40];
	char* param_array[] = { NULL, NULL, NULL, NULL };

	g_snprintf(dest_ip, 30, "string:%s", ip_addr);
	g_snprintf(netmask, 30, "string:255.255.255.255");
	g_snprintf(if_name, 40, "string:%s", interface);

	param_array[0] = dest_ip;
	param_array[1] = netmask;
	param_array[2] = if_name;

	message = _net_invoke_dbus_method(NETCONFIG_SERVICE, NETCONFIG_NETWORK_PATH,
			NETCONFIG_NETWORK_INTERFACE, "RemoveRoute", param_array, &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Failed to Remove route\n");
		goto done;
	}

	/** Check Reply */
	DBusMessageIter iter;
	int remove_result = 0;

	dbus_message_iter_init(message, &iter);
	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_BOOLEAN) {
		dbus_message_iter_get_basic(&iter, &remove_result);
		NETWORK_LOG(NETWORK_HIGH, "Remove route, result : %d\n", remove_result);
	}

	if (remove_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	dbus_message_unref(message);

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
		 NETWORK_LOG(NETWORK_ERROR, "Error!! Invalid EventCb parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ClientEventCb != NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application Already registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_ALREADY_REGISTERED;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		if (_net_mutex_init() != NET_ERR_NONE) {
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}

		Error = _net_register_signal();
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to register DBus signal [%s]\n",
					_net_print_error(Error));
			_net_mutex_destroy();

			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		NetworkInfo.wifi_state = _net_get_wifi_state();
		_net_init_service_state_table();
	}

	g_atomic_int_inc(&NetworkInfo.ref_count);

	NetworkInfo.ClientEventCb = event_cb;
	NetworkInfo.user_data = user_data;

	NETWORK_LOG(NETWORK_HIGH, "Client Register Successfully\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int net_register_client_ext(net_event_cb_t event_cb, net_device_t client_type, void *user_data)
{
	net_err_t Error = NET_ERR_NONE;

	if (event_cb == NULL || (client_type != NET_DEVICE_DEFAULT && client_type != NET_DEVICE_WIFI)) {
		 NETWORK_LOG(NETWORK_ERROR, "Error!! Invalid EventCb parameter\n");
		return NET_ERR_INVALID_PARAM;
	}

	switch (client_type) {
	case NET_DEVICE_DEFAULT:
		if (NetworkInfo.ClientEventCb_conn != NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! Connection CAPI Already registered\n");
			return NET_ERR_APP_ALREADY_REGISTERED;
		}
		break;
	case NET_DEVICE_WIFI:
		if (NetworkInfo.ClientEventCb_wifi != NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! Wi-Fi CAPI Already registered\n");
			return NET_ERR_APP_ALREADY_REGISTERED;
		}
	default:
		break;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		if (_net_mutex_init() != NET_ERR_NONE)
			return NET_ERR_UNKNOWN;

		Error = _net_register_signal();
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to register DBus signal [%s]\n",
					_net_print_error(Error));
			_net_mutex_destroy();
			return Error;
		}

		NetworkInfo.wifi_state = _net_get_wifi_state();
		_net_init_service_state_table();
	}

	g_atomic_int_inc(&NetworkInfo.ref_count);

	switch (client_type) {
	case NET_DEVICE_DEFAULT:
		NetworkInfo.ClientEventCb_conn = event_cb;
		NetworkInfo.user_data_conn = user_data;
		break;
	case NET_DEVICE_WIFI:
		NetworkInfo.ClientEventCb_wifi = event_cb;
		NetworkInfo.user_data_wifi = user_data;
	default:
		break;
	}

	NETWORK_LOG(NETWORK_HIGH, "Client Register Successfully\n");

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

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0 ||
	    NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (g_atomic_int_dec_and_test(&NetworkInfo.ref_count)) {
		_net_deregister_signal();
		_net_mutex_destroy();
		_net_clear_request_table();
	}

	NetworkInfo.ClientEventCb = NULL;
	NetworkInfo.user_data = NULL;
	NETWORK_LOG(NETWORK_HIGH, "Client De-Register Successfully\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int net_deregister_client_ext(net_device_t client_type)
{
	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		return NET_ERR_APP_NOT_REGISTERED;
	}

	switch (client_type) {
	case NET_DEVICE_DEFAULT:
		if (NetworkInfo.ClientEventCb_conn == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! Connection CAPI was not registered\n");
			return NET_ERR_APP_NOT_REGISTERED;
		}
		NetworkInfo.ClientEventCb_conn = NULL;
		NetworkInfo.user_data_conn = NULL;
		break;
	case NET_DEVICE_WIFI:
		if (NetworkInfo.ClientEventCb_wifi == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! Wi-Fi CAPI was not registered\n");
			return NET_ERR_APP_NOT_REGISTERED;
		}
		NetworkInfo.ClientEventCb_wifi = NULL;
		NetworkInfo.user_data_wifi = NULL;
		break;
	default:
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid client_type parameter\n");
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_dec_and_test(&NetworkInfo.ref_count)) {
		_net_deregister_signal();
		_net_mutex_destroy();
		_net_clear_request_table();
	}

	NETWORK_LOG(NETWORK_HIGH, "Client De-Register Successfully\n");
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
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Active(default) network is cellular type.\n");
		Error = NET_ERR_NO_SERVICE;
	} else if (active_profile_info.profile_type == NET_DEVICE_ETHERNET) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Active(default) network is ethernet type.\n");
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
	char state[CONNMAN_STATE_STRLEN] = ""; /** Possible value are "online", "offline" and "connected" */
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;
	
	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if ((Error = _net_dbus_get_state(state)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! failed to get state. Error [%s]\n",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return FALSE;
	}

	if ((strcmp(state, "online") == 0) || (strcmp(state, "connected") == 0)) {
		NETWORK_LOG(NETWORK_HIGH, "State [%s]\n", state);
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

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG( NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if ((Error = _net_dbus_get_network_status(device_type, network_status)) != NET_ERR_NONE) {
		NETWORK_LOG( NETWORK_ERROR, "Error!!! failed to get network status. Error [%s]\n",  
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
		NETWORK_LOG(NETWORK_ERROR,
			"Error!!! Failed to get statistics info. error : [%s]\n",
			_net_print_error(Error));

	return Error;
}

EXPORT_API int net_set_statistics(net_device_t device_type, net_statistics_type_e statistics_type)
{
	net_err_t Error = NET_ERR_NONE;

	if ((Error = _net_dbus_set_statistics(device_type, statistics_type)) != NET_ERR_NONE )
		NETWORK_LOG(NETWORK_ERROR,
			"Error!!! Failed to set statistics info. error : [%s]\n",
			_net_print_error(Error));

	return Error;
}

EXPORT_API int net_add_route(const char *ip_addr, const char *interface)
{
	net_err_t Error = NET_ERR_NONE;

	if (ip_addr == NULL || strlen(ip_addr) < 7 || interface == NULL || strlen(interface) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_add_route(ip_addr, interface);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! failed to add route. Error [%s]\n",
				_net_print_error(Error));
		return Error;
	}

	return Error;
}

EXPORT_API int net_remove_route(const char *ip_addr, const char *interface)
{
	net_err_t Error = NET_ERR_NONE;

	if (ip_addr == NULL || strlen(ip_addr) < 7 || interface == NULL || strlen(interface) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_remove_route(ip_addr, interface);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! failed to remove route. Error [%s]\n",
				_net_print_error(Error));
		return Error;
	}

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
		
	NETWORK_LOG(NETWORK_HIGH, "ProfileName [%s] passed\n", profile_name);

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid ProfileName passed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! pending call already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name);

	if ((Error = _net_dbus_open_connection(profile_name)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!! Failed to request open connection, Error [%s]\n", 
				_net_print_error(Error));

		if(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
					0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Connect Request Success for ProfileName[%s]\n", profile_name);
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
EXPORT_API int net_open_connection_with_preference(net_service_type_t service_type)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t profile_name;
	memset(&profile_name, 0, sizeof(net_profile_name_t));

	if (_net_is_valid_service_type(service_type) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Service Type passed\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! pending call already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	Error = _net_get_service_profile(service_type, &profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! Failed to find service\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name.ProfileName);

	if ((Error = _net_dbus_open_connection(profile_name.ProfileName)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!! Failed to request open connection, Error [%s]\n",
				_net_print_error(Error));

		if(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
					0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Connect Request Success for ProfileName[%s]\n",
			profile_name.ProfileName);
	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int net_open_connection_with_preference_ext(net_service_type_t service_type, net_profile_name_t *prof_name)
{
	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t profile_name;
	memset(&profile_name, 0, sizeof(net_profile_name_t));

	if (_net_is_valid_service_type(service_type) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Service Type passed\n");
		return NET_ERR_INVALID_PARAM;
	}

	if (prof_name == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid profile name passed\n");
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! Request already in progress\n");
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! pending call already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	Error = _net_get_service_profile(service_type, &profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! Failed to find service\n");
		return Error;
	}

	request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name.ProfileName);

	if ((Error = _net_dbus_open_connection(profile_name.ProfileName)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!! Failed to request open connection, Error [%s]\n",
				_net_print_error(Error));

		if(request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_OPEN_CONNECTION],
					0, sizeof(network_request_table_t));

		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Connect Request Success for ProfileName[%s]\n",
			profile_name.ProfileName);

	memcpy(prof_name, &profile_name, sizeof(net_profile_name_t));
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

	NETWORK_LOG(NETWORK_HIGH, "ProfileName [%s] passed\n", profile_name);

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		 NETWORK_LOG(NETWORK_ERROR, "Error!! Invalid ProfileName parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (g_atomic_int_get(&NetworkInfo.ref_count) == 0) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE &&
	    __net_dbus_abort_open_request(profile_name) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! pending call already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag = TRUE;
	snprintf(request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].ProfileName,
			NET_PROFILE_NAME_LEN_MAX+1, "%s", profile_name);

	if ((Error = _net_dbus_close_connection(profile_name)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!! Failed to request close connection, Error [%s]\n", 
				_net_print_error(Error));
	
		if (request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION].flag == TRUE)
			memset(&request_table[NETWORK_REQUEST_TYPE_CLOSE_CONNECTION],
					0, sizeof(network_request_table_t));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}
	
	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
