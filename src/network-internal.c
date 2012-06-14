/*
 * Copyright 2012  Samsung Electronics Co., Ltd
 *
 * Licensed under the Flora License, Version 1.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.tizenopensource.org/license
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
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

#include <sys/types.h>
#include <sys/wait.h>

#include <fcntl.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <linux/if_ether.h>

/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

#include "network-internal.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

#define EAP_CONFIG_KEY_TYPE			"Type"
#define EAP_CONFIG_KEY_NAME			"Name"
#define EAP_CONFIG_KEY_SSID			"SSID"
#define EAP_CONFIG_KEY_EAP				"EAP"
#define EAP_CONFIG_KEY_IDENTITY		"Identity"
#define EAP_CONFIG_KEY_PASSPHRASE	"Passphrase"

#define EAP_CONFIG_KEY_CA_CERT		"CACertFile"
#define EAP_CONFIG_KEY_CL_CERT		"ClientCertFile"
#define EAP_CONFIG_KEY_PRV_KEY		"PrivateKeyFile"
#define EAP_CONFIG_KEY_PRV_KEY_PASS	"PrivateKeyPassphrase"
#define EAP_CONFIG_KEY_PRV_KEY_PASS_TYPE  "PrivateKeyPassphraseType"
#define EAP_CONFIG_KEY_PHASE2			"Phase2"

#define EAP_TYPE_LEN_MAX 			8		//tls / ttls / peap
#define EAP_AUTH_TYPE_LEN_MAX		16
#define EAP_TYPE_STR_TLS	"tls"
#define EAP_TYPE_STR_TTLS	"ttls"
#define EAP_TYPE_STR_PEAP	"peap"

#define CONNMAN_STORAGE_DIR		"/var/lib/connman"

/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/


/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

/*****************************************************************************
 * 	Extern Global Variables
 *****************************************************************************/
extern network_info_t NetworkInfo;


/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/

/** set all request to FALSE (0) */
network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX] = {{0, }, };

struct {
	pthread_mutex_t callback_mutex;
	pthread_mutex_t wifi_state_mutex;
} networkinfo_mutex;

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

gboolean __convert_eap_type_to_string(gchar eap_type, char * eap_str)
{
	switch(eap_type)
	{
		case WLAN_SEC_EAP_TYPE_PEAP:
			memcpy(eap_str, EAP_TYPE_STR_PEAP, EAP_TYPE_LEN_MAX);
			return TRUE;
		case WLAN_SEC_EAP_TYPE_TLS:
			memcpy(eap_str, EAP_TYPE_STR_TLS, EAP_TYPE_LEN_MAX);
			return TRUE;
		case WLAN_SEC_EAP_TYPE_TTLS:
			memcpy(eap_str, EAP_TYPE_STR_TTLS, EAP_TYPE_LEN_MAX);
			return TRUE;
		case WLAN_SEC_EAP_TYPE_SIM:		//Not supported yet
		case WLAN_SEC_EAP_TYPE_AKA:		//Not supported yet
		default:
			return FALSE;
	}

}

void __convert_eap_auth_to_string(gchar eap_auth, char * auth_str)
{
	switch(eap_auth)
	{
		case WLAN_SEC_EAP_AUTH_NONE:
			return ;
		case WLAN_SEC_EAP_AUTH_PAP:
			memcpy(auth_str, "PAP", strlen("PAP")+1);
			break;
		case WLAN_SEC_EAP_AUTH_MSCHAP:
			memcpy(auth_str, "MSCHAP", strlen("MSCHAP")+1);
			break;
		case WLAN_SEC_EAP_AUTH_MSCHAPV2:
			memcpy(auth_str, "MSCHAPV2", strlen("MSCHAPV2")+1);
			break;
		case WLAN_SEC_EAP_AUTH_GTC:
			memcpy(auth_str, "GTC", strlen("GTC")+1);
			break;
		case WLAN_SEC_EAP_AUTH_MD5:
			memcpy(auth_str, "MD5", strlen("MD5")+1);
			break;
		default:
			return ;

	}
}

static void __update_config(GKeyFile * keyfile, char * group,
							const wlan_eap_info_t * eap_info, const char * essid,
							char * eap_type, char * auth_type)
{
	g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_TYPE, "wifi");

	NETWORK_LOG(NETWORK_HIGH, "------------eap info------------------");
	NETWORK_LOG(NETWORK_HIGH, "-essid : %s", essid);
	NETWORK_LOG(NETWORK_HIGH, "-eap type : %s", eap_type);
	NETWORK_LOG(NETWORK_HIGH, "-phase2 authentication type : %s", auth_type);
	NETWORK_LOG(NETWORK_HIGH, "-username : %s", eap_info->username);
	NETWORK_LOG(NETWORK_HIGH, "-password : %s", eap_info->password);
	NETWORK_LOG(NETWORK_HIGH, "-ca certi filename : %s", eap_info->ca_cert_filename);
	NETWORK_LOG(NETWORK_HIGH, "-client certi filename : %s", eap_info->client_cert_filename);
	NETWORK_LOG(NETWORK_HIGH, "-private key filename : %s", eap_info->private_key_filename);
	NETWORK_LOG(NETWORK_HIGH, "-private key password : %s", eap_info->private_key_passwd);
	NETWORK_LOG(NETWORK_HIGH, "--------------------------------------");

	if(essid != NULL)
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_NAME, essid);

	if(eap_type != NULL)
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_EAP, eap_type);

	if(auth_type != NULL)
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_PHASE2, auth_type);

	if((eap_info->username != NULL) && (strlen(eap_info->username) > 0))
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_IDENTITY, eap_info->username);

	if((eap_info->password != NULL) && (strlen(eap_info->password) > 0))
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_PASSPHRASE, eap_info->password);

	if((eap_info->ca_cert_filename != NULL) && (strlen(eap_info->ca_cert_filename) > 0))
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_CA_CERT, eap_info->ca_cert_filename);

	if((eap_info->client_cert_filename != NULL) && (strlen(eap_info->client_cert_filename) > 0))
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_CL_CERT, eap_info->client_cert_filename);

	if((eap_info->private_key_filename != NULL) && (strlen(eap_info->private_key_filename) > 0))
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_PRV_KEY, eap_info->private_key_filename);

	if((eap_info->private_key_passwd != NULL) && (strlen(eap_info->private_key_passwd) > 0))
		g_key_file_set_string(keyfile, group, EAP_CONFIG_KEY_PRV_KEY_PASS, eap_info->private_key_passwd);
}

static net_err_t __net_add_eap_config(const wlan_eap_info_t * eap_info, const char * essid)
{
	GKeyFile * keyfile;
	char group[16];
	char * eap_str;
	char * auth_str;
	gchar *data = NULL;
	gsize length = 0;
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;

	if((eap_info->eap_type < WLAN_SEC_EAP_TYPE_PEAP) || (eap_info->eap_type > WLAN_SEC_EAP_TYPE_AKA)) {
		NETWORK_LOG(NETWORK_HIGH, "Invalid EAP type (%d)\n", eap_info->eap_type);
		return NET_ERR_INVALID_PARAM;
	}

	eap_str = (char*)calloc(EAP_TYPE_LEN_MAX, sizeof(char));
	if(eap_str == NULL)
		return NET_ERR_UNKNOWN;

	if(__convert_eap_type_to_string(eap_info->eap_type, eap_str) == FALSE) {
		NETWORK_LOG(NETWORK_HIGH, "Invalid EAP type (%d)\n", eap_info->eap_type);
		NET_MEMFREE(eap_str);
		return NET_ERR_INVALID_PARAM;
	}

	auth_str = (char*)calloc(EAP_AUTH_TYPE_LEN_MAX, sizeof(char));
	if(auth_str == NULL) {
		NET_MEMFREE(eap_str);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	__convert_eap_auth_to_string(eap_info->eap_auth, auth_str);

	sprintf(group, "service_%s", eap_str);
	NETWORK_LOG(NETWORK_HIGH, "group (%s)\n", group);

	keyfile = g_key_file_new();

	__update_config(keyfile, group, eap_info, essid, eap_str, auth_str);

	data = g_key_file_to_data(keyfile, &length, NULL);

	NETWORK_LOG(NETWORK_ERROR, "-----length of data : %d\n", length);
	Error = _net_dbus_provision_service(data, length+1);
	if(Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR, "Failed to update EAP info in ConnMan\n");

	NET_MEMFREE(eap_str);
	NET_MEMFREE(auth_str);

	g_key_file_free(keyfile);
	g_free(data);

	return Error;

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
	default:
		return "INVALID";
	}
}

net_device_t _net_get_tech_type_from_path(const char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_device_t device_type = NET_DEVICE_UNKNOWN;

	if (strstr(profile_name, "/wifi_") != NULL)
		device_type = NET_DEVICE_WIFI;
	else if (strstr(profile_name, "/cellular_") != NULL)
		device_type = NET_DEVICE_CELLULAR;

	__NETWORK_FUNC_EXIT__;
	return device_type;
}

char* _net_get_string(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessageIter args;
	char* sigvalue = NULL;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_STRING) {
		NETWORK_LOG(NETWORK_LOW, "Argument is not string\n");
	} else {
		dbus_message_iter_get_basic(&args, &sigvalue);
	}

	__NETWORK_FUNC_EXIT__;
	return sigvalue;
}

char* _net_get_object(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessageIter args;
	char* sigvalue = NULL;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_OBJECT_PATH) {
		NETWORK_LOG(NETWORK_LOW, "Argument is not string\n");
	} else {
		dbus_message_iter_get_basic(&args, &sigvalue);
	}

	__NETWORK_FUNC_EXIT__;
	return sigvalue;
}

int _net_get_boolean(DBusMessage* msg)
{
	__NETWORK_FUNC_ENTER__;

	DBusMessageIter args;
	dbus_bool_t val = FALSE;
	int retvalue = FALSE;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
	} else if (dbus_message_iter_get_arg_type(&args) != DBUS_TYPE_BOOLEAN) {
		NETWORK_LOG(NETWORK_LOW, "Argument is not boolean\n");
	} else {
		dbus_message_iter_get_basic(&args, &val);

		if (val)
			retvalue = TRUE;
		else
			retvalue = FALSE;
	}

	__NETWORK_FUNC_EXIT__;
	return retvalue;
}

int _net_get_path(DBusMessage *msg, char *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	char* ProfileName = NULL;

	ProfileName = (char*)dbus_message_get_path(msg);
	snprintf(profile_name, strlen(ProfileName) + 1, "%s", ProfileName);

	__NETWORK_FUNC_EXIT__;

	return NET_ERR_NONE;
}

int _net_get_tech_state(DBusMessage* msg, network_get_tech_state_info_t* tech_state)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessageIter args, dict;

	if (!dbus_message_iter_init(msg, &args)) {
		NETWORK_LOG(NETWORK_LOW, "Message does not have parameters\n");
		Error = NET_ERR_UNKNOWN;
		goto done;
	}

	dbus_message_iter_recurse(&args, &dict);

	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter key_iter, sub_iter1, sub_iter2;
		const char *key = NULL;
		const char *tech_name = NULL;

		dbus_message_iter_recurse(&dict, &key_iter);
		dbus_message_iter_get_basic(&key_iter, &key);

		if (strcmp(key, "AvailableTechnologies") == 0 ||
		    strcmp(key, "EnabledTechnologies") == 0 ||
		    strcmp(key, "ConnectedTechnologies") == 0) {
			dbus_message_iter_next(&key_iter);
			dbus_message_iter_recurse(&key_iter, &sub_iter1);

			if (dbus_message_iter_get_arg_type(&sub_iter1) == DBUS_TYPE_ARRAY)
				dbus_message_iter_recurse(&sub_iter1, &sub_iter2);
			else
				goto next_dict;

			while (dbus_message_iter_get_arg_type(&sub_iter2) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_iter2, &tech_name);
				if (tech_name != NULL &&
				    strcmp(tech_name, tech_state->technology) == 0) {
					if (strcmp(key, "AvailableTechnologies") == 0)
						tech_state->AvailableTechnology = TRUE;
					else if (strcmp(key, "EnabledTechnologies") == 0)
						tech_state->EnabledTechnology = TRUE;
					else
						tech_state->ConnectedTechnology = TRUE;
				}

				dbus_message_iter_next(&sub_iter2);
			}
		} else if (strcmp(key, "DefaultTechnology") == 0) {
			dbus_message_iter_next(&key_iter);
			dbus_message_iter_recurse(&key_iter, &sub_iter1);

			if (dbus_message_iter_get_arg_type(&sub_iter1) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_iter1, &tech_name);
				if (tech_name != NULL &&
				    strcmp(tech_name, tech_state->technology) == 0)
					tech_state->AvailableTechnology = TRUE;
			}
		}
next_dict:
		dbus_message_iter_next(&dict);
	}

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}


/** This function is used only to open Wi-Fi connection with hidden APs */
int _net_open_connection_with_wifi_info(const net_wifi_connection_info_t* wifi_info)
{
	__NETWORK_FUNC_ENTER__;

	/** path = manager.ConnectService(({ "Type": "wifi", "Mode": "managed",
	 "SSID": sys.argv[1],
	 "Security": security,
	 "Passphrase": passphrase }));
	*/

	net_err_t Error = NET_ERR_NONE;
	char type[] = "wifi";
	char mode[128] = "";
	char essid[NET_WLAN_ESSID_LEN + 1] = "";
	char security[128] = "";
	char passphrase[NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN] = "";
	net_wifi_connect_service_info_t wifi_connection_info;

	snprintf(mode, 128, "%s", (wifi_info->wlan_mode == NETPM_WLAN_CONNMODE_ADHOC)?"adhoc":"managed");

	switch(wifi_info->security_info.sec_mode) {
	case WLAN_SEC_MODE_NONE:
		snprintf(security, 128, "%s", "none");
		snprintf(passphrase, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN, "%s", "");
		break;

	case WLAN_SEC_MODE_WEP:
		snprintf(security, 128, "%s", "wep");
		snprintf(passphrase, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN, "%s", wifi_info->security_info.authentication.wep.wepKey);
		break;

	/** WPA-PSK(equivalent to WPA-NONE in case of Ad-Hoc) */
	case WLAN_SEC_MODE_WPA_PSK:
		snprintf(security, 128, "%s", "psk");
		snprintf(passphrase, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN, "%s", wifi_info->security_info.authentication.psk.pskKey);
		break;

	/** WPA2-PSK */
	/** WPA-PSK / WPA2-PSK supported */
	case WLAN_SEC_MODE_WPA2_PSK:
		snprintf(security, 128, "%s", "rsn");
		snprintf(passphrase, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN, "%s", wifi_info->security_info.authentication.psk.pskKey);
		break;

	case WLAN_SEC_MODE_IEEE8021X:
		snprintf(security, 128, "%s", "ieee8021x");
		snprintf(passphrase, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN, "%s", "");
		Error = __net_add_eap_config(&(wifi_info->security_info.authentication.eap), wifi_info->essid);
		if(Error != NET_ERR_NONE) {
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
		break;

	default:
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid security type\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	snprintf(essid, NET_WLAN_ESSID_LEN + 1, "%s", wifi_info->essid);

	wifi_connection_info.type = type;
	wifi_connection_info.mode = mode;
	wifi_connection_info.ssid = essid;
	wifi_connection_info.security = security;
	wifi_connection_info.passphrase = passphrase;

	NETWORK_LOG( NETWORK_HIGH,
			"Parameters: type:\t%s\nmode:\t%s\nssid:\t%s\nsecurity:\t%s\npassphrase:\t%s\n",
			wifi_connection_info.type, wifi_connection_info.mode,
			wifi_connection_info.ssid, wifi_connection_info.security,
			wifi_connection_info.passphrase);

	if( (Error = _net_dbus_connect_service(&wifi_connection_info)) != NET_ERR_NONE ) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Failed to request connect_service. Error [%s]\n",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Successfully requested to ConnMan\n");

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_mutex_init()
{
	__NETWORK_FUNC_ENTER__;

	if (pthread_mutex_init(&networkinfo_mutex.callback_mutex, NULL) != 0) {
		NETWORK_LOG(NETWORK_ERROR, "Mutex for callback initialization failed!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	if (pthread_mutex_init(&networkinfo_mutex.wifi_state_mutex, NULL) != 0) {
		NETWORK_LOG(NETWORK_ERROR, "Mutex for wifi state initialization failed!\n");
		pthread_mutex_destroy(&networkinfo_mutex.callback_mutex);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

void _net_mutex_destroy()
{
	__NETWORK_FUNC_ENTER__;

	pthread_mutex_destroy(&networkinfo_mutex.callback_mutex);
	pthread_mutex_destroy(&networkinfo_mutex.wifi_state_mutex);

	__NETWORK_FUNC_EXIT__;
}

void _net_client_callback(net_event_info_t *event_data)
{
	pthread_mutex_lock(&networkinfo_mutex.callback_mutex);
	__NETWORK_FUNC_ENTER__;

	NETWORK_CALLBACK(event_data, NetworkInfo.user_data);

	__NETWORK_FUNC_EXIT__;
	pthread_mutex_unlock(&networkinfo_mutex.callback_mutex);
}

net_wifi_state_t _net_get_wifi_state()
{
	pthread_mutex_lock(&networkinfo_mutex.wifi_state_mutex);
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	network_get_tech_state_info_t tech_state = {{0,},};
	net_wifi_state_t wifi_state = WIFI_UNKNOWN;

	snprintf(tech_state.technology, NET_TECH_LENGTH_MAX, "%s", "wifi");
	Error = _net_dbus_get_technology_state(&tech_state);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"Error!!! _net_dbus_get_technology_state() failed. Error [%s]\n",
			_net_print_error(Error));
		goto state_done;
	}

	if (tech_state.EnabledTechnology == TRUE)
		wifi_state = WIFI_ON;
	else
		wifi_state = WIFI_OFF;

state_done:
	__NETWORK_FUNC_EXIT__;
	pthread_mutex_unlock(&networkinfo_mutex.wifi_state_mutex);
	return wifi_state;
}

void _net_clear_request_table()
{
	__NETWORK_FUNC_ENTER__;

	int i = 0;

	for (i = 0;i < NETWORK_REQUEST_TYPE_MAX;i++)
		memset(&request_table[i], 0, sizeof(network_request_table_t));

	__NETWORK_FUNC_EXIT__;
}

#ifdef __cplusplus
}
#endif /* __cplusplus */
