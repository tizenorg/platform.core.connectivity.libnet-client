/*
 * Network Client Library
 *
 * Copyright 2011-2013 Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.0 (the "License");
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

#ifndef __NETWORK_DBUS_REQUEST_H__
#define __NETWORK_DBUS_REQUEST_H__

#include "network-internal.h"
#include "network-wifi-intf.h"

#ifdef __cplusplus
extern "C" {
#endif

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

#define NETCONFIG_AGENT_FIELD_PASSPHRASE 	"Passphrase"
#define NETCONFIG_AGENT_FIELD_WPS_PBC		"WPS_PBC"
#define NETCONFIG_AGENT_FIELD_WPS_PIN		"WPS_PIN"

#define CONNMAN_CONFIG_FIELD_TYPE "Type"
#define CONNMAN_CONFIG_FIELD_NAME "Name"
#define CONNMAN_CONFIG_FIELD_SSID "SSID"
#define CONNMAN_CONFIG_FIELD_EAP_METHOD "EAP"
#define CONNMAN_CONFIG_FIELD_IDENTITY "Identity"
#define CONNMAN_CONFIG_FIELD_PASSPHRASE "Passphrase"
#define CONNMAN_CONFIG_FIELD_PHASE2 "Phase2"
#define CONNMAN_CONFIG_FIELD_CA_CERT_FILE "CACertFile"
#define CONNMAN_CONFIG_FIELD_CLIENT_CERT_FILE "ClientCertFile"
#define CONNMAN_CONFIG_FIELD_PVT_KEY_FILE "PrivateKeyFile"
#define CONNMAN_CONFIG_FIELD_PVT_KEY_PASSPHRASE "PrivateKeyPassphrase"

/*****************************************************************************
 * 	Global Structures
 *****************************************************************************/

typedef struct {
	char *type;
	char *mode;
	char *ssid;
	char *security;
	char *passphrase;
	char *eap_type;
	char *eap_auth;
	char *identity;
	char *password;
	char *ca_cert_file;
	char *client_cert_file;
	char *private_key_file;
	char *private_key_password;
} net_wifi_connect_service_info_t;

/*****************************************************************************
 * 	Global Functions 
 *****************************************************************************/
int _net_dbus_scan_request(void);
int _net_dbus_set_bgscan_mode(net_wifi_background_scan_mode_t mode);
int _net_dbus_get_state(char* state);
int _net_dbus_set_agent_passphrase(const char *passphrase);
int _net_dbus_set_agent_wps_pbc(void);
int _net_dbus_set_agent_wps_pin(char *wps_pin);
int _net_dbus_open_connection(const char* profile_name);
int _net_dbus_close_connection(const char* profile_name);
int _net_dbus_get_network_status(net_device_t device_type, net_cm_network_status_t* network_status);
int _net_dbus_get_tech_status(net_device_t device_type, net_tech_info_t* tech_status);
int _net_dbus_connect_service(const net_wifi_connect_service_info_t* wifi_connection_info);
int _net_dbus_set_profile_ipv4(net_profile_info_t* prof_info, char* profile_name);
int _net_dbus_set_profile_dns(net_profile_info_t* prof_info, char* profile_name);
int _net_dbus_set_proxy(net_profile_info_t* prof_info, char* profile_name);
int _net_dbus_get_technology_state(network_tech_state_info_t* tech_state);
DBusMessage *_net_invoke_dbus_method(const char* dest, const char* path,
		char* interface_name, char* method,
		char* param_array[], int* dbus_error);
int _net_invoke_dbus_method_nonblock(const char* dest, const char* path,
		char* interface_name, char* method,
		DBusPendingCallNotifyFunction notify_func);
int _net_dbus_load_wifi_driver(void);
int _net_dbus_remove_wifi_driver(void);
int _net_dbus_get_statistics(net_device_t device_type, net_statistics_type_e statistics_type, unsigned long long *size);
int _net_dbus_set_statistics(net_device_t device_type, net_statistics_type_e statistics_type);
int _net_dbus_add_pdp_profile(net_profile_info_t *prof_info);
int _net_dbus_modify_pdp_profile(net_profile_info_t *prof_info, const char *profile_name);
dbus_bool_t _net_dbus_is_pending_call_used(void);
void _net_dbus_set_pending_call_used(dbus_bool_t used);
DBusPendingCall *_net_dbus_get_pending_call(void);
void _net_dbus_set_pending_call(DBusPendingCall *call);
void _net_dbus_clear_pending_call(void);
gboolean __net_dbus_abort_open_request(const char *profile_name);
int _net_dbus_specific_scan_request(const char *ssid);
int _net_dbus_set_default(const char* profile_name);

#ifdef __cplusplus
}
#endif

#endif /** __NETWORK_SIGNAL_HANDLER_H__ */
