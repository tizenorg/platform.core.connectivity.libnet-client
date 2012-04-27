/*
 *
 * Network Client Library
 *
 * Copyright (c) 2012 Samsung Electronics Co., Ltd All Rights Reserved.
 *
 * PROPRIETARY/CONFIDENTIAL
 * This software is the confidential and proprietary information of
 * SAMSUNG ELECTRONICS ("Confidential Information").
 * You shall not disclose such Confidential Information and shall
 * use it only in accordance with the terms of the license agreement
 * you entered into with SAMSUNG ELECTRONICS.
 * SAMSUNG make no representations or warranties about the suitability
 * of the software, either express or implied, including but not limited
 * to the implied warranties of merchantability, fitness for a particular
 * purpose, or non-infringement. SAMSUNG shall not be liable for
 * any damages suffered by licensee as a result of using, modifying or
 * distributing this software or its derivatives.
 *
 */


#ifndef __NETWORK_DBUS_REQUEST_H_
#define __NETWORK_DBUS_REQUEST_H_

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



/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/
	
#define CONNMAN_CLIENT_DBUS_TYPE_STRING 	"string"
#define CONNMAN_CLIENT_DBUS_TYPE_INT16 		"int16"
#define CONNMAN_CLIENT_DBUS_TYPE_UINT16		"uint16"
#define CONNMAN_CLIENT_DBUS_TYPE_INT32		"int32"
#define CONNMAN_CLIENT_DBUS_TYPE_UINT32		"uint32"
#define CONNMAN_CLIENT_DBUS_TYPE_INT64		"int64"
#define CONNMAN_CLIENT_DBUS_TYPE_UINT64		"uint64"
#define CONNMAN_CLIENT_DBUS_TYPE_DOUBLE		"double"
#define CONNMAN_CLIENT_DBUS_TYPE_BYTE		"byte"
#define CONNMAN_CLIENT_DBUS_TYPE_BOOLEAN	"boolean"
#define CONNMAN_CLIENT_DBUS_TYPE_OBJECT_PATH	"objpath"

#define CONNMAN_CLIENT_DBUS_TYPE_VARIANT	"variant"
#define CONNMAN_CLIENT_DBUS_TYPE_ARRAY		"array"
#define CONNMAN_CLIENT_DBUS_TYPE_DICT_ENTRY	"dict"


/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/

typedef struct
{
	char* type;
	char* mode;
	char* ssid;
	char* security;
	char* passphrase; /** TODO handle EAP */
} net_wifi_connect_service_info_t;


/*****************************************************************************
 * 	Global Functions 
 *****************************************************************************/
int _net_dbus_scan_request(void);
int _net_dbus_provision_service(gchar * config_str, int len);
int _net_dbus_set_bgscan_mode(net_wifi_background_scan_mode_t mode);
int _net_dbus_get_state(char* state);
int _net_send_dbus_request(const char* destination, char *param_array[], DBusMessage** result);
int _net_dbus_open_connection(const char* profile_name);
int _net_dbus_close_connection(const char* profile_name);
int _net_dbus_get_network_status (net_device_t device_type, net_cm_network_status_t* network_status);
int _net_dbus_connect_service(const net_wifi_connect_service_info_t* wifi_connection_info);
int _net_dbus_set_profile_ipv4(net_profile_info_t* prof_info, char* profile_name);
int _net_dbus_set_profile_dns(net_profile_info_t* prof_info, char* profile_name);
int _net_dbus_set_proxy(net_profile_info_t* prof_info, char* profile_name);
int _net_dbus_get_technology_state(network_get_tech_state_info_t* tech_state);
DBusMessage *_net_invoke_dbus_method(const char* dest, DBusConnection *connection,
		const char* path, char* interface_name, char* method, int *dbus_error);
int _net_dbus_load_wifi_driver(void);
int _net_dbus_remove_wifi_driver(void);
int _net_dbus_add_pdp_profile(net_profile_info_t *prof_info);
int _net_dbus_modify_pdp_profile(net_profile_info_t *prof_info, const char *profile_name);
dbus_bool_t _net_dbus_is_pending_call_used(void);
void _net_dbus_set_pending_call_used(dbus_bool_t used);
DBusPendingCall *_net_dbus_get_pending_call(void);
void _net_dbus_set_pending_call(DBusPendingCall *call);

#endif /** __NETWORK_SIGNAL_HANDLER_H_ */
