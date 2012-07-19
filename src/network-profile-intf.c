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
#include <ctype.h> 



/*****************************************************************************
 * 	Platform headers
 *****************************************************************************/

#include "network-internal.h"
#include "network-dbus-request.h"

/*****************************************************************************
 * 	Macros and Typedefs
 *****************************************************************************/

/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/
static int __net_extract_wifi_info(DBusMessageIter *array, net_profile_info_t* ProfInfo);
static int __net_get_profile_info(const char* ProfileName, net_profile_info_t* ProfInfo);
static int __net_extract_service_info(const char* ProfileName,
		DBusMessage *message, net_profile_info_t* ProfInfo);
static int __net_pm_init_profile_info(net_device_t profile_type, net_profile_info_t* ProfInfo);
static int __net_telephony_init_profile_info(net_telephony_profile_info_t* ProfInfo);
static int __net_telephony_get_profile_info(net_profile_name_t* ProfileName,
		net_telephony_profile_info_t* ProfileInfo);
static int __net_telephony_get_profile_list(net_profile_name_t** ProfileName, int* ProfileCount);
static int __net_extract_wifi_services(DBusMessage* message,
		DBusMessageIter* dict, network_services_list_t* service_info);
static int __net_extract_mobile_services(DBusMessage* message, DBusMessageIter* dict, 
		network_services_list_t* service_info, net_service_type_t network_type);
static int __net_extract_services(DBusMessage *message, net_device_t device_type,
		net_profile_info_t** profile_info, int* profile_count);
static int __net_extract_ip(DBusMessageIter *iter, net_addr_t *ipAddr);
static int __net_extract_common_info(const char *key, DBusMessageIter *variant, net_profile_info_t* ProfInfo);
static int __net_extract_mobile_info(DBusMessageIter *array, net_profile_info_t* ProfInfo);
static int __net_telephony_search_pdp_profile(char* ProfileName, net_profile_name_t* PdpProfName);
static int __net_telephony_modify_profile(const char* ProfileName,
		net_profile_info_t* ProfInfo, net_profile_info_t* exProfInfo);
static int __net_modify_wlan_profile_info(const char* ProfileName,
		net_profile_info_t* ProfInfo, net_profile_info_t* exProfInfo);
static int __net_telephony_delete_profile(net_profile_name_t* PdpProfName);
static int __net_wifi_delete_profile(net_profile_name_t* WifiProfName);
static int __net_telephony_add_profile(net_profile_info_t *ProfInfo, net_service_type_t network_type);
static int __net_extract_defult_profile(DBusMessageIter* iter, net_profile_name_t *profile_name);
static int __net_set_profile_property(char* path, char* key, char* value);

/*****************************************************************************
 * 	Global Functions
 *****************************************************************************/

/*****************************************************************************
 * 	Extern Variables
 *****************************************************************************/

extern network_info_t NetworkInfo;

/*****************************************************************************
 * 	Global Variables
 *****************************************************************************/

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/

static int __net_pm_init_profile_info(net_device_t profile_type, net_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	int i = 0;
	net_dev_info_t* net_info = NULL;
	
	if (ProfInfo == NULL ||
		(profile_type != NET_DEVICE_WIFI && profile_type != NET_DEVICE_CELLULAR)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		return NET_ERR_INVALID_PARAM;
	}

	memset(ProfInfo->ProfileName, '\0', NET_PROFILE_NAME_LEN_MAX+1);
	ProfInfo->Favourite = FALSE;

	if (profile_type == NET_DEVICE_WIFI) {
		ProfInfo->profile_type = NET_DEVICE_WIFI;
		memset(ProfInfo->ProfileInfo.Wlan.essid, '\0', NET_WLAN_ESSID_LEN+1);
		memset(ProfInfo->ProfileInfo.Wlan.bssid, '\0', NET_MAX_MAC_ADDR_LEN+1);
		ProfInfo->ProfileInfo.Wlan.Strength = 0;
		ProfInfo->ProfileInfo.Wlan.frequency = 0;
		ProfInfo->ProfileInfo.Wlan.max_rate = 0;
		ProfInfo->ProfileInfo.Wlan.wlan_mode = 0;
		ProfInfo->ProfileInfo.Wlan.PassphraseRequired = FALSE;
		
		ProfInfo->ProfileInfo.Wlan.security_info.sec_mode = 0;
		ProfInfo->ProfileInfo.Wlan.security_info.enc_mode = 0;

		if (NETPM_WLAN_MAX_WEP_KEY_LEN >= NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN)
			memset(ProfInfo->ProfileInfo.Wlan.security_info.authentication.wep.wepKey,
					'\0', NETPM_WLAN_MAX_WEP_KEY_LEN+1);
		else
			memset(ProfInfo->ProfileInfo.Wlan.security_info.authentication.psk.pskKey,
					'\0', NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN+1);

		ProfInfo->ProfileInfo.Wlan.security_info.wps_support = FALSE;

		net_info = &(ProfInfo->ProfileInfo.Wlan.net_info);
	} else if(profile_type == NET_DEVICE_CELLULAR) {
		ProfInfo->profile_type = NET_DEVICE_CELLULAR;
		ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_NONE;
		ProfInfo->ProfileInfo.Pdp.ServiceType = NET_SERVICE_UNKNOWN;
		ProfInfo->ProfileInfo.Pdp.Apn[0] = '\0';
		ProfInfo->ProfileInfo.Pdp.AuthInfo.AuthType = NET_PDP_AUTH_NONE;
		ProfInfo->ProfileInfo.Pdp.AuthInfo.UserName[0] = '\0';
		ProfInfo->ProfileInfo.Pdp.AuthInfo.Password[0] = '\0';
		ProfInfo->ProfileInfo.Pdp.HomeURL[0] = '\0';
		ProfInfo->ProfileInfo.Pdp.Mcc[0] = '\0';
		ProfInfo->ProfileInfo.Pdp.Mnc[0] = '\0';
		ProfInfo->ProfileInfo.Pdp.IsStatic = FALSE;
		ProfInfo->ProfileInfo.Pdp.Roaming = FALSE;
		ProfInfo->ProfileInfo.Pdp.SetupRequired = FALSE;

		net_info = &(ProfInfo->ProfileInfo.Pdp.net_info);
	}
	
	memset(net_info->ProfileName, '\0', NET_PROFILE_NAME_LEN_MAX+1);
	memset(net_info->DevName, '\0', NET_MAX_DEVICE_NAME_LEN+1);
	net_info->DnsCount = 0;

	for (i = 0;i < NET_DNS_ADDR_MAX;i++) {
		net_info->DnsAddr[i].Type = NET_ADDR_IPV4;
		net_info->DnsAddr[i].Data.Ipv4.s_addr = 0;
	}

	net_info->IpConfigType = 0;
	net_info->IpAddr.Type = NET_ADDR_IPV4;
	net_info->IpAddr.Data.Ipv4.s_addr = 0;
	net_info->BNetmask = FALSE;
	net_info->SubnetMask.Type = NET_ADDR_IPV4;
	net_info->SubnetMask.Data.Ipv4.s_addr = 0;
	net_info->BDefGateway = FALSE;
	net_info->GatewayAddr.Type = NET_ADDR_IPV4;
	net_info->GatewayAddr.Data.Ipv4.s_addr = 0;
	net_info->ProxyMethod = NET_PROXY_TYPE_UNKNOWN;
	memset(net_info->ProxyAddr, '\0', NET_PROXY_LEN_MAX+1);
	memset(net_info->MacAddr, '\0', NET_MAX_MAC_ADDR_LEN+1);
	
	__NETWORK_FUNC_EXIT__;
	
	return NET_ERR_NONE;
}

static int __net_telephony_init_profile_info(net_telephony_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;
	
	if (ProfInfo == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	memset(ProfInfo->ProfileName, '\0', NET_PROFILE_NAME_LEN_MAX+1);
	ProfInfo->ServiceType = NET_SERVICE_UNKNOWN;
	memset(ProfInfo->Apn, '\0', NET_PDP_APN_LEN_MAX+1);

	ProfInfo->AuthInfo.AuthType = NET_PDP_AUTH_NONE;
	memset(ProfInfo->AuthInfo.UserName, '\0', NET_PDP_AUTH_USERNAME_LEN_MAX+1);
	memset(ProfInfo->AuthInfo.Password, '\0', NET_PDP_AUTH_PASSWORD_LEN_MAX+1);

	memset(ProfInfo->ProxyAddr, '\0', NET_PROXY_LEN_MAX+1);
	memset(ProfInfo->HomeURL, '\0', NET_HOME_URL_LEN_MAX+1);
	
	__NETWORK_FUNC_EXIT__;
	
	return NET_ERR_NONE;
}

static int __net_telephony_get_profile_info(net_profile_name_t* ProfileName, net_telephony_profile_info_t* ProfileInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessage* result = NULL;
	DBusMessageIter iter, array;
	
	if (ProfileName == NULL || ProfileInfo == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid parameter!\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	char request[] = TELEPHONY_PROFILE_INTERFACE ".GetProfile";
	char* param_array[] = {NULL, NULL, NULL};
	
	param_array[0] = ProfileName->ProfileName;
	param_array[1] = request;

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s]\n",
		param_array[0],
		param_array[1]);
	
	if ((Error = _net_send_dbus_request(TELEPHONY_SERVCE, param_array, &result)) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! _net_send_dbus_request failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	/* Parsing profile info */
	dbus_message_iter_init(result, &iter);
	dbus_message_iter_recurse(&iter, &array);

	Error = __net_telephony_init_profile_info(ProfileInfo);

	if (Error != NET_ERR_NONE) {
		dbus_message_unref(result);
		__NETWORK_FUNC_EXIT__;

		return Error;
	}

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry;
		const char *key = NULL;
		const char *value = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);

		if (strcmp(key, "path") == 0) {
			dbus_message_iter_get_basic(&entry, &value);
			
			if (value != NULL)
				g_strlcpy(ProfileInfo->ProfileName, value, NET_PROFILE_NAME_LEN_MAX);

		} else if (strcmp(key, "svc_ctg_id") == 0) {
			net_service_type_t ServiceType = NET_SERVICE_UNKNOWN;
			dbus_message_iter_get_basic(&entry, &value);

			if (value != NULL)
				ServiceType = atoi(value);

			if (ServiceType > NET_SERVICE_UNKNOWN)
				ProfileInfo->ServiceType = ServiceType;

		} else if (strcmp(key, "apn") == 0) {
			dbus_message_iter_get_basic(&entry, &value);
			
			if (value != NULL)
				g_strlcpy(ProfileInfo->Apn, value, NET_PDP_APN_LEN_MAX);

		} else if (strcmp(key, "auth_type") == 0) {
			net_auth_type_t authType = NET_PDP_AUTH_NONE;
			dbus_message_iter_get_basic(&entry, &value);
			
			if (value != NULL)
				authType = atoi(value);

			if (authType == NET_PDP_AUTH_PAP)
				ProfileInfo->AuthInfo.AuthType = NET_PDP_AUTH_PAP;
			else if (authType == NET_PDP_AUTH_CHAP)
				ProfileInfo->AuthInfo.AuthType = NET_PDP_AUTH_CHAP;

		} else if (strcmp(key, "auth_id") == 0) {
			dbus_message_iter_get_basic(&entry, &value);

			if (value != NULL)
				g_strlcpy(ProfileInfo->AuthInfo.UserName, value, NET_PDP_AUTH_USERNAME_LEN_MAX);

		} else if (strcmp(key, "auth_pwd") == 0) {
			dbus_message_iter_get_basic(&entry, &value);

			if (value != NULL)
				g_strlcpy(ProfileInfo->AuthInfo.Password, value, NET_PDP_AUTH_PASSWORD_LEN_MAX);

		} else if (strcmp(key, "proxy_addr") == 0) {
			dbus_message_iter_get_basic(&entry, &value);

			if (value != NULL)
				g_strlcpy(ProfileInfo->ProxyAddr, value, NET_PROXY_LEN_MAX);

		} else if (strcmp(key, "home_url") == 0) {
			dbus_message_iter_get_basic(&entry, &value);

			if (value != NULL)
				g_strlcpy(ProfileInfo->HomeURL, value, NET_HOME_URL_LEN_MAX);
		}
		dbus_message_iter_next(&array);
	}

	dbus_message_unref(result);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_telephony_get_profile_list(net_profile_name_t** ProfileName, int* ProfileCount)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessage* result = NULL;
	net_profile_name_t* profileList = NULL;
	DBusMessageIter iter, array;
	int count = 0;

	char request[] = TELEPHONY_MASTER_INTERFACE ".GetProfileList";
	char path[] = TELEPHONY_MASTER_PATH;
	char* param_array[] = {NULL, NULL, NULL};
	
	param_array[0] = path;
	param_array[1] = request;

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s]\n",
		param_array[0],
		param_array[1]);
	
	Error = _net_send_dbus_request(TELEPHONY_SERVCE, param_array, &result);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! _net_send_dbus_request failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	dbus_message_iter_init(result, &iter);
	if (dbus_message_iter_get_arg_type(&iter) != DBUS_TYPE_ARRAY) {
		NETWORK_LOG(NETWORK_HIGH,  "There is no profiles\n");
		*ProfileCount = 0;
		dbus_message_unref(result);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	dbus_message_iter_recurse(&iter, &array);

	/* Get count of profile name from reply message */
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		count++;
		dbus_message_iter_next(&array);
	}

	if (count > 0)
		profileList = (net_profile_name_t*)malloc(sizeof(net_profile_name_t) * count);
	else {
		*ProfileCount = 0;
		dbus_message_unref(result);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (profileList == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Failed to allocate memory\n");
		*ProfileCount = 0;
		dbus_message_unref(result);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	count = 0;

	/* Parsing to get profile name from reply message */
	dbus_message_iter_init(result, &iter);
	dbus_message_iter_recurse(&iter, &array);
	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_STRING) {
		const char *key = NULL;

		dbus_message_iter_get_basic(&array, &key);

		if (key != NULL)
			g_strlcpy(profileList[count].ProfileName, key, NET_PROFILE_NAME_LEN_MAX);

		count++;
		dbus_message_iter_next(&array);
	}

	*ProfileName = profileList;
	*ProfileCount = count;

	dbus_message_unref(result);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_telephony_search_pdp_profile(char* ProfileName, net_profile_name_t* PdpProfName)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t* ProfileList = NULL;
	char* connmanProfName = NULL;
	char* telephonyProfName = NULL;
	char* foundPtr = NULL;
	int ProfileCount = 0;
	int i = 0;

	/* Get pdp profile list from telephony service */
	Error = __net_telephony_get_profile_list(&ProfileList, &ProfileCount);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! failed to get profile list from telephony service\n");
		NET_MEMFREE(ProfileList);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (ProfileList == NULL || ProfileCount <= 0) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! There is no PDP profiles\n");
		NET_MEMFREE(ProfileList);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NO_SERVICE;
	}

	/* Find matching profile */
	connmanProfName = strrchr(ProfileName, '/') + 1;
	for (i = 0;i < ProfileCount;i++) {
		telephonyProfName = strrchr(ProfileList[i].ProfileName, '/') + 1;
		foundPtr = strstr(connmanProfName, telephonyProfName);

		if (foundPtr != NULL && strcmp(foundPtr, telephonyProfName) == 0) {
			g_strlcpy(PdpProfName->ProfileName,
					ProfileList[i].ProfileName, NET_PROFILE_NAME_LEN_MAX);
			NETWORK_LOG(NETWORK_HIGH,
					"PDP profile name found in cellular profile: %s\n",
					PdpProfName->ProfileName);
			break;
		}
	}

	if (i >= ProfileCount) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! There is no matching PDP profiles\n");
		NET_MEMFREE(ProfileList);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NO_SERVICE;
	}

	NET_MEMFREE(ProfileList);
	__NETWORK_FUNC_EXIT__;

	return Error;
}

static int __net_extract_wifi_services(DBusMessage* message,
		DBusMessageIter* dict, network_services_list_t* service_info)
{
	int count = 0;
	int i = 0;

	__NETWORK_FUNC_ENTER__;	

	if(message == NULL || dict == NULL || service_info == NULL)
	{
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid prarameter \n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}
	
	while(dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY)
	{
		DBusMessageIter keyValue, array, value;
		const char *key = NULL;
		const char *objPath = NULL;

		dbus_message_iter_recurse(dict, &keyValue);
		dbus_message_iter_get_basic(&keyValue, &key);

		if(strcmp(key, "Services") == 0)
		{
			dbus_message_iter_next(&keyValue);
			dbus_message_iter_recurse(&keyValue, &array);
			if(dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY)
			{
				NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get service list\n");
				__NETWORK_FUNC_EXIT__;
				return NET_ERR_NO_SERVICE;
			}
				
			dbus_message_iter_recurse(&array, &value);
			if(dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_OBJECT_PATH)
			{
				NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get service list\n");
				__NETWORK_FUNC_EXIT__;
				return NET_ERR_NO_SERVICE;
			}

			while(dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH)
			{
				dbus_message_iter_get_basic(&value, &objPath);

				if(strstr(objPath, "wifi_") != NULL)
				{
					service_info->ProfileName[count] = (char*)malloc(NET_PROFILE_NAME_LEN_MAX+1);
					if(service_info->ProfileName[count] == NULL)
					{
						NETWORK_LOG(NETWORK_EXCEPTION,
								"Error!!! Failed to allocate memory\n");

						for(i = 0;i < count;i++)
							NET_MEMFREE(service_info->ProfileName[i]);
						
						__NETWORK_FUNC_EXIT__;	
						return NET_ERR_UNKNOWN;
					}

					g_strlcpy(service_info->ProfileName[count], objPath, NET_PROFILE_NAME_LEN_MAX);

					count++;
				}

				dbus_message_iter_next(&value);
			}

			service_info->num_of_services = count;
			return NET_ERR_NONE;
		}				

		dbus_message_iter_next(dict);
	}		

	__NETWORK_FUNC_EXIT__;

	return NET_ERR_NONE;
}

static int __net_extract_mobile_services(DBusMessage* message, DBusMessageIter* dict,
		network_services_list_t* service_info, net_service_type_t network_type)
{
	int count = 0;
	int i = 0;
	const char net_suffix[] = "_1";
	const char mms_suffix[] = "_2";
	const char wap_suffix[] = "_3";
	char *suffix = NULL;

	__NETWORK_FUNC_ENTER__;	
	
	if (message == NULL || dict == NULL || service_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid prarameter \n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	while (dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter keyValue, array, value;
		const char *key = NULL;
		const char *objPath = NULL;
		char found = FALSE;

		dbus_message_iter_recurse(dict, &keyValue);
		dbus_message_iter_get_basic(&keyValue, &key);

		if (strcmp(key, "Services") == 0) {
			dbus_message_iter_next(&keyValue);
			dbus_message_iter_recurse(&keyValue, &array);

			if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY) {
				NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get service list\n");
				__NETWORK_FUNC_EXIT__;
				return NET_ERR_NO_SERVICE;
			}
				
			dbus_message_iter_recurse(&array, &value);

			if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_OBJECT_PATH) {
				NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get service list\n");
				__NETWORK_FUNC_EXIT__;
				return NET_ERR_NO_SERVICE;
			}

			while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH) {
				dbus_message_iter_get_basic(&value, &objPath);

				if (strstr(objPath, "cellular_") != NULL) {
					found = FALSE;

					suffix = strrchr(objPath, '_');

					if (network_type == NET_SERVICE_UNKNOWN)
						found = TRUE;
					else if (network_type == NET_SERVICE_MMS && strcmp(suffix, mms_suffix) == 0)
						found = TRUE;
					else if (network_type == NET_SERVICE_WAP && strcmp(suffix, wap_suffix) == 0)
						found = TRUE;
					else if (network_type == NET_SERVICE_INTERNET && strcmp(suffix, net_suffix) == 0)
						found = TRUE;

					if (found) {
						service_info->ProfileName[count] = (char*)malloc(NET_PROFILE_NAME_LEN_MAX+1);
						if (service_info->ProfileName[count] == NULL) {
							NETWORK_LOG(NETWORK_EXCEPTION,
									"Error!!! Failed to allocate memory\n");

							for (i = 0;i < count;i++)
								NET_MEMFREE(service_info->ProfileName[i]);
							
							__NETWORK_FUNC_EXIT__;	
							return NET_ERR_UNKNOWN;
						}

						g_strlcpy(service_info->ProfileName[count], objPath, NET_PROFILE_NAME_LEN_MAX+1);
						
						NETWORK_LOG(NETWORK_HIGH, "index [%d] ProfileName [%s]\n",
								count, service_info->ProfileName[count]);

						count++;
					}
				}

				dbus_message_iter_next(&value);
			}
			service_info->num_of_services = count;
		}

		dbus_message_iter_next(dict);
	}

	__NETWORK_FUNC_EXIT__;

	return NET_ERR_NONE;
}

static int __net_extract_services(DBusMessage *message, net_device_t device_type,
		net_profile_info_t** profile_info, int* profile_count)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessageIter iter, dict;
	network_services_list_t service_info = {0,};
	net_profile_info_t ProfileInfo = {0, };
	net_profile_info_t* ProfilePtr = NULL;
	int i = 0;
	int j = 0;	
	int profiles = 0;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	*profile_count = 0;

	switch (device_type) {
	case NET_DEVICE_WIFI :
		Error = __net_extract_wifi_services(message, &dict, &service_info);
		break;
	case NET_DEVICE_CELLULAR :
		Error = __net_extract_mobile_services(message, &dict, &service_info, NET_SERVICE_UNKNOWN);
		break;
	default :
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NOT_SUPPORTED;
		break;
	}
	
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't extract services from received message\n");
		*profile_count = 0;
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	NETWORK_LOG(NETWORK_HIGH, "Num. of Profiles from Manager : [%d]\n", service_info.num_of_services);

	profiles = 0;
	for (i = 0; i < service_info.num_of_services; i++) {
		memset(&ProfileInfo, 0, sizeof(net_profile_info_t));

		Error = __net_get_profile_info(service_info.ProfileName[i], &ProfileInfo);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Error!!! failed to get service(profile) information. Error [%s]\n",
					_net_print_error(Error));
			NETWORK_LOG(NETWORK_HIGH, "Continuing with next profile\n");

			continue;
		}

		profiles++;
		ProfilePtr = (net_profile_info_t*)realloc(ProfilePtr, (j + 1) * sizeof(net_profile_info_t));
		if (ProfilePtr == NULL) {
			NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Failed to allocate memory\n");

			for (i = 0;i < service_info.num_of_services;i++)
				NET_MEMFREE(service_info.ProfileName[i]);

			__NETWORK_FUNC_EXIT__;
			return NET_ERR_UNKNOWN;
		}

		memcpy(ProfilePtr + j, &ProfileInfo, sizeof(net_profile_info_t));
		j++;
	}

	for(i = 0;i < service_info.num_of_services;i++)
		NET_MEMFREE(service_info.ProfileName[i]);

	NETWORK_LOG(NETWORK_HIGH, "Total Num. of Profiles [%d]\n", profiles);

	*profile_count = profiles;
	*profile_info = ProfilePtr;

	__NETWORK_FUNC_EXIT__;

	return Error;
}


static int __net_extract_ip(DBusMessageIter *iter, net_addr_t *ipAddr)
{
	__NETWORK_FUNC_ENTER__;

	unsigned char *ipValue = NULL;
	const char *value = NULL;
	char *saveptr = NULL;
	char ipString[NETPM_IPV4_STR_LEN_MAX+1];
	char* ipToken[4];
	
	dbus_message_iter_get_basic(iter, &value);	

	ipValue = (unsigned char *)&(ipAddr->Data.Ipv4.s_addr);

	if(value != NULL) {
		g_strlcpy(ipString, value, NETPM_IPV4_STR_LEN_MAX+1);

		ipToken[0] = strtok_r(ipString, ".", &saveptr);

		if(ipToken[0] != NULL) {
			ipToken[1] = strtok_r(NULL, ".", &saveptr);

			if(ipToken[1] != NULL) {
				ipToken[2] = strtok_r(NULL, ".", &saveptr);

				if(ipToken[2] != NULL) {
					ipToken[3] = strtok_r(NULL, ".", &saveptr);

					if(ipToken[3] != NULL) {
						ipValue[0] = (unsigned char)atoi(ipToken[0]);
						ipValue[1] = (unsigned char)atoi(ipToken[1]);
						ipValue[2] = (unsigned char)atoi(ipToken[2]);
						ipValue[3] = (unsigned char)atoi(ipToken[3]);
					}
				}
			}
		}
	}

	__NETWORK_FUNC_EXIT__;

	return NET_ERR_NONE;
}

static int __net_extract_common_info(const char *key, DBusMessageIter *variant, net_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessageIter subIter1, subIter2, subIter3, subIter4;
	const char *subKey = NULL;
	const char *value = NULL;
	net_dev_info_t* net_info = NULL;
	
	if (ProfInfo->profile_type == NET_DEVICE_CELLULAR) {
		net_info = &(ProfInfo->ProfileInfo.Pdp.net_info);
	} else if (ProfInfo->profile_type == NET_DEVICE_WIFI) {
		net_info = &(ProfInfo->ProfileInfo.Wlan.net_info);
	} else {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Invalid Profile type. [%d]\n", ProfInfo->profile_type);
		return NET_ERR_INVALID_PARAM;
	}

	if (strcmp(key, "State") == 0) {
		dbus_message_iter_get_basic(variant, &value);
		
		if (strcmp(value, "idle") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_IDLE;
		else if (strcmp(value, "failure") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_FAILURE;
		else if (strcmp(value, "association") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_ASSOCIATION;
		else if (strcmp(value, "configuration") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_CONFIGURATION;
		else if (strcmp(value, "ready") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_READY;
		else if (strcmp(value, "disconnect") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_DISCONNECT;
		else if (strcmp(value, "online") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_ONLINE;
		else
			ProfInfo->ProfileState = NET_STATE_TYPE_UNKNOWN;
	} else if (strcmp(key, "Favorite") == 0) {
		dbus_bool_t val;
		
		dbus_message_iter_get_basic(variant, &val);
		
		if(val)
			ProfInfo->Favourite = TRUE;
		else
			ProfInfo->Favourite = FALSE;
	} else if (strcmp(key, "Ethernet") == 0) {
		dbus_message_iter_recurse(variant, &subIter1);
		
		while (dbus_message_iter_get_arg_type(&subIter1) == DBUS_TYPE_DICT_ENTRY) {
			dbus_message_iter_recurse(&subIter1, &subIter2);
			dbus_message_iter_get_basic(&subIter2, &subKey);

			if (strcmp(subKey, "Interface") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				dbus_message_iter_get_basic(&subIter3, &value);

				if (value != NULL)
					g_strlcpy(net_info->DevName, value, NET_MAX_DEVICE_NAME_LEN);

			} else if (strcmp(subKey, "Address") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				dbus_message_iter_get_basic(&subIter3, &value);

				if (value != NULL)
					g_strlcpy(net_info->MacAddr, value, NET_MAX_MAC_ADDR_LEN);
			}
			
			dbus_message_iter_next(&subIter1);
		}
	} else if (strcmp(key, "IPv4") == 0) {
		dbus_message_iter_recurse(variant, &subIter1);
		
		while (dbus_message_iter_get_arg_type(&subIter1) == DBUS_TYPE_DICT_ENTRY) {
			dbus_message_iter_recurse(&subIter1, &subIter2);
			dbus_message_iter_get_basic(&subIter2, &subKey);

			if (strcmp(subKey, "Method") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				dbus_message_iter_get_basic(&subIter3, &value);
				
				if (strcmp(value, "dhcp") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_DYNAMIC;
				else if (strcmp(value, "manual") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_STATIC;
				else if (strcmp(value, "fixed") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_FIXED;
				else if (strcmp(value, "off") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_OFF;

			} else if (strcmp(subKey, "Address") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				__net_extract_ip(&subIter3, &net_info->IpAddr);
			} else if (strcmp(subKey, "Netmask") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				__net_extract_ip(&subIter3, &net_info->SubnetMask);
				net_info->BNetmask = TRUE;
			} else if (strcmp(subKey, "Gateway") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				__net_extract_ip(&subIter3, &net_info->GatewayAddr);
				net_info->BDefGateway = TRUE;
			}
			
			dbus_message_iter_next(&subIter1);
		}
	} else if (strcmp(key, "IPv4.Configuration") == 0) {

		if (net_info->IpConfigType != NET_IP_CONFIG_TYPE_DYNAMIC &&
		    net_info->IpConfigType != NET_IP_CONFIG_TYPE_STATIC &&
		    net_info->IpConfigType != NET_IP_CONFIG_TYPE_OFF) {

			dbus_message_iter_recurse(variant, &subIter1);
		
			while (dbus_message_iter_get_arg_type(&subIter1) == DBUS_TYPE_DICT_ENTRY) {
				dbus_message_iter_recurse(&subIter1, &subIter2);
				dbus_message_iter_get_basic(&subIter2, &subKey);

				if (strcmp(subKey, "Method") == 0) {
					dbus_message_iter_next(&subIter2);
					dbus_message_iter_recurse(&subIter2, &subIter3);
					dbus_message_iter_get_basic(&subIter3, &value);
					
					if(strcmp(value, "dhcp") == 0)
						net_info->IpConfigType = NET_IP_CONFIG_TYPE_DYNAMIC;
					else if(strcmp(value, "manual") == 0)
						net_info->IpConfigType = NET_IP_CONFIG_TYPE_STATIC;
					else if(strcmp(value, "off") == 0)
						net_info->IpConfigType = NET_IP_CONFIG_TYPE_OFF;

				} else if (strcmp(subKey, "Address") == 0 &&
				           net_info->IpAddr.Data.Ipv4.s_addr == 0) {
					dbus_message_iter_next(&subIter2);
					dbus_message_iter_recurse(&subIter2, &subIter3);
					__net_extract_ip(&subIter3, &net_info->IpAddr);
				} else if (strcmp(subKey, "Netmask") == 0 &&
				           net_info->SubnetMask.Data.Ipv4.s_addr == 0) {
					dbus_message_iter_next(&subIter2);
					dbus_message_iter_recurse(&subIter2, &subIter3);
					__net_extract_ip(&subIter3, &net_info->SubnetMask);
					net_info->BNetmask = TRUE;
				} else if (strcmp(subKey, "Gateway") == 0 &&
				           net_info->GatewayAddr.Data.Ipv4.s_addr == 0) {
					dbus_message_iter_next(&subIter2);
					dbus_message_iter_recurse(&subIter2, &subIter3);
					__net_extract_ip(&subIter3, &net_info->GatewayAddr);
					net_info->BDefGateway = TRUE;
				}
				
				dbus_message_iter_next(&subIter1);
			}
		}
	} else if(strcmp(key, "Nameservers") == 0) {
		int dnsCount = 0;
		dbus_message_iter_recurse(variant, &subIter1);			
		
		while (dbus_message_iter_get_arg_type(&subIter1) == DBUS_TYPE_STRING) {
			__net_extract_ip(&subIter1, &net_info->DnsAddr[dnsCount]);
			dnsCount++;
			if (dnsCount >= NET_DNS_ADDR_MAX)
				break;					
			
			dbus_message_iter_next(&subIter1);
		}

		net_info->DnsCount = dnsCount;
	} else if (strcmp(key, "Nameservers.Configuration") == 0 && net_info->DnsCount == 0) {
		int dnsCount = 0;
		dbus_message_iter_recurse(variant, &subIter1);

		while (dbus_message_iter_get_arg_type(&subIter1) == DBUS_TYPE_STRING) {
			__net_extract_ip(&subIter1, &net_info->DnsAddr[dnsCount]);
			dnsCount++;
			if(dnsCount >= NET_DNS_ADDR_MAX)
				break;
			
			dbus_message_iter_next(&subIter1);
		}

		net_info->DnsCount = dnsCount;
	} else if (strcmp(key, "Domains") == 0) {
	} else if (strcmp(key, "Domains.Configuration") == 0) {
	} else if (strcmp(key, "Proxy") == 0) {
		dbus_message_iter_recurse(variant, &subIter1);
		
		while (dbus_message_iter_get_arg_type(&subIter1) == DBUS_TYPE_DICT_ENTRY) {
			dbus_message_iter_recurse(&subIter1, &subIter2);
			dbus_message_iter_get_basic(&subIter2, &subKey);

			if (strcmp(subKey, "Method") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				dbus_message_iter_get_basic(&subIter3, &value);
				
				if (strcmp(value, "direct") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_DIRECT;
				else if (strcmp(value, "auto") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_AUTO;
				else if (strcmp(value, "manual") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_MANUAL;
				else
					net_info->ProxyMethod = NET_PROXY_TYPE_UNKNOWN;
			} else if (strcmp(subKey, "URL") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				dbus_message_iter_get_basic(&subIter3, &value);

				if (value != NULL)
					g_strlcpy(net_info->ProxyAddr, value, NET_PROXY_LEN_MAX);

			} else if (strcmp(subKey, "Servers") == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);

				if (dbus_message_iter_get_arg_type(&subIter3) == DBUS_TYPE_ARRAY) {
					dbus_message_iter_recurse(&subIter3, &subIter4);

					if (dbus_message_iter_get_arg_type(&subIter4) == DBUS_TYPE_STRING) {
						dbus_message_iter_get_basic(&subIter4, &value);

						if (value != NULL)
							g_strlcpy(net_info->ProxyAddr, value, NET_PROXY_LEN_MAX);
					}
				}
			}
			
			dbus_message_iter_next(&subIter1);
		}
	} else if (strcmp(key, "Proxy.Configuration") == 0 &&
	           (net_info->ProxyMethod == NET_PROXY_TYPE_UNKNOWN ||
	            strlen(net_info->ProxyAddr) == 0)) {

		dbus_message_iter_recurse(variant, &subIter1);

		while (dbus_message_iter_get_arg_type(&subIter1) == DBUS_TYPE_DICT_ENTRY) {
			dbus_message_iter_recurse(&subIter1, &subIter2);
			dbus_message_iter_get_basic(&subIter2, &subKey);

			if (strcmp(subKey, "Method") == 0 &&
			   net_info->ProxyMethod == NET_PROXY_TYPE_UNKNOWN) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				dbus_message_iter_get_basic(&subIter3, &value);

				if (strcmp(value, "direct") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_DIRECT;
				else if (strcmp(value, "auto") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_AUTO;
				else if (strcmp(value, "manual") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_MANUAL;
				else
					net_info->ProxyMethod = NET_PROXY_TYPE_UNKNOWN;
			} else if (strcmp(subKey, "URL") == 0 && strlen(net_info->ProxyAddr) == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);
				dbus_message_iter_get_basic(&subIter3, &value);

				if (value != NULL)
					g_strlcpy(net_info->ProxyAddr, value, NET_PROXY_LEN_MAX+1);

			} else if (strcmp(subKey, "Servers") == 0 && strlen(net_info->ProxyAddr) == 0) {
				dbus_message_iter_next(&subIter2);
				dbus_message_iter_recurse(&subIter2, &subIter3);

				if (dbus_message_iter_get_arg_type(&subIter3) == DBUS_TYPE_ARRAY) {
					dbus_message_iter_recurse(&subIter3, &subIter4);

					if (dbus_message_iter_get_arg_type(&subIter4) == DBUS_TYPE_STRING) {
						dbus_message_iter_get_basic(&subIter4, &value);

						if (value != NULL)
							g_strlcpy(net_info->ProxyAddr, value, NET_PROXY_LEN_MAX+1);
					}
				}
			}

			dbus_message_iter_next(&subIter1);
		}
	} else if(strcmp(key, "Provider") == 0) {
	}

	__NETWORK_FUNC_EXIT__;
	
	return Error;
}

static int __net_extract_wifi_info(DBusMessageIter *array, net_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_wifi_profile_info_t *Wlan = &(ProfInfo->ProfileInfo.Wlan);

	while (dbus_message_iter_get_arg_type(array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant, sub_array;
		const char *key = NULL;
		const char *value = NULL;
		
		dbus_message_iter_recurse(array, &entry);
		dbus_message_iter_get_basic(&entry, &key);		

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &variant);		

		if (strcmp(key, "Mode") == 0) {
			dbus_message_iter_get_basic(&variant, &value);

			if (strcmp(value, "managed") == 0)
				Wlan->wlan_mode = NETPM_WLAN_CONNMODE_INFRA;
			else if (strcmp(value, "adhoc") == 0)
				Wlan->wlan_mode = NETPM_WLAN_CONNMODE_ADHOC;
			else
				Wlan->wlan_mode = NETPM_WLAN_CONNMODE_AUTO;
		} else if (strcmp(key, "Security") == 0) {
			dbus_message_iter_recurse(&variant, &sub_array);

			while (dbus_message_iter_get_arg_type(&sub_array) == DBUS_TYPE_STRING) {
				dbus_message_iter_get_basic(&sub_array, &value);
				if (strcmp(value, "none") == 0 &&
				    Wlan->security_info.sec_mode < WLAN_SEC_MODE_NONE)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_NONE;
				else if (strcmp(value, "wep") == 0 &&
				         Wlan->security_info.sec_mode < WLAN_SEC_MODE_WEP)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WEP;
				else if (strcmp(value, "psk") == 0 &&
				         Wlan->security_info.sec_mode < WLAN_SEC_MODE_WPA_PSK)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WPA_PSK;
				else if (strcmp(value, "ieee8021x") == 0 &&
				         Wlan->security_info.sec_mode < WLAN_SEC_MODE_IEEE8021X)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_IEEE8021X;
				else if (strcmp(value, "wpa") == 0 &&
				         Wlan->security_info.sec_mode < WLAN_SEC_MODE_WPA_PSK)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WPA_PSK;
				else if (strcmp(value, "rsn") == 0 &&
				         Wlan->security_info.sec_mode < WLAN_SEC_MODE_WPA_PSK)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WPA2_PSK;
				else if (strcmp(value, "wps") == 0)
					Wlan->security_info.wps_support = TRUE;
				else if (Wlan->security_info.sec_mode < WLAN_SEC_MODE_NONE)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_NONE;

				dbus_message_iter_next(&sub_array);
			}
		} else if (strcmp(key, "EncryptionMode") == 0) {
			dbus_message_iter_get_basic(&variant, &value);

			if (strcmp(value, "none") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_NONE;
			else if (strcmp(value, "wep") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_WEP;
			else if (strcmp(value, "tkip") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_TKIP;
			else if (strcmp(value, "aes") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_AES;
			else if (strcmp(value, "mixed") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_TKIP_AES_MIXED;

			dbus_message_iter_next(&sub_array);

		} else if (strcmp(key, "Strength") == 0) {
			dbus_message_iter_get_basic(&variant, &(Wlan->Strength));
		} else if (strcmp(key, "Name") == 0) {
			dbus_message_iter_get_basic(&variant, &value);

			if (value != NULL)
				g_strlcpy(Wlan->essid, value, NET_WLAN_ESSID_LEN);

		} else if (strcmp(key, "Passphrase") == 0) {
			wlan_security_info_t *security_info = &(Wlan->security_info);
			dbus_message_iter_get_basic(&variant, &value);

			if (security_info->sec_mode == WLAN_SEC_MODE_WEP && value != NULL)
				g_strlcpy(security_info->authentication.wep.wepKey,
						value, NETPM_WLAN_MAX_WEP_KEY_LEN+1);
			else if ((security_info->sec_mode == WLAN_SEC_MODE_WPA_PSK ||
			            security_info->sec_mode == WLAN_SEC_MODE_WPA2_PSK) &&
			            value != NULL)
				g_strlcpy(security_info->authentication.psk.pskKey,
						value, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN+1);

		} else if (strcmp(key, "PassphraseRequired") == 0) {
			dbus_bool_t val;
			
			dbus_message_iter_get_basic(&variant, &val);

			if(val)
				Wlan->PassphraseRequired = TRUE;
			else
				Wlan->PassphraseRequired = FALSE;
		} else if (strcmp(key, "BSSID") == 0) {
			dbus_message_iter_get_basic(&variant, &value);

			if (value != NULL)
				g_strlcpy(Wlan->bssid, value, NET_MAX_MAC_ADDR_LEN);

		} else if (strcmp(key, "MaxRate") == 0) {
			unsigned int maxrate;
			dbus_message_iter_get_basic(&variant, &maxrate);

			Wlan->max_rate = maxrate;

		} else if (strcmp(key, "Frequency") == 0) {
			unsigned short frequency;
			dbus_message_iter_get_basic(&variant, &frequency);

			Wlan->frequency = (unsigned int)frequency;

		} else {
			__net_extract_common_info(key, &variant, ProfInfo);
		}
		
		dbus_message_iter_next(array);
	}

	__NETWORK_FUNC_EXIT__;

	return Error;
}

static int __net_extract_mobile_info(DBusMessageIter *array, net_profile_info_t* ProfInfo)
{
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;	

	while (dbus_message_iter_get_arg_type(array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, variant;
		const char *key = NULL;
		const char *value = NULL;
		
		dbus_message_iter_recurse(array, &entry);
		dbus_message_iter_get_basic(&entry, &key);

		dbus_message_iter_next(&entry);
		dbus_message_iter_recurse(&entry, &variant);

		if (strcmp(key, "Mode") == 0) {
			dbus_message_iter_get_basic(&variant, &value);

			if (strcmp(value, "gprs") == 0)
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_GPRS;
			else if (strcmp(value, "edge") == 0)
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_EDGE;
			else if (strcmp(value, "umts") == 0)
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_UMTS;
			else
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_NONE;
		} else if (strcmp(key, "Roaming") == 0) {
			dbus_bool_t val;
			
			dbus_message_iter_get_basic(&variant, &val);

			if (val)
				ProfInfo->ProfileInfo.Pdp.Roaming = TRUE;
			else
				ProfInfo->ProfileInfo.Pdp.Roaming = FALSE;
		} else if (strcmp(key, "SetupRequired") == 0) {
			dbus_bool_t val;
			
			dbus_message_iter_get_basic(&variant, &val);

			if (val)
				ProfInfo->ProfileInfo.Pdp.SetupRequired = TRUE;
			else
				ProfInfo->ProfileInfo.Pdp.SetupRequired = FALSE;
		} else
			__net_extract_common_info(key, &variant, ProfInfo);

		dbus_message_iter_next(array);
	}

	/* Get Specific info from telephony service */
	net_telephony_profile_info_t telephony_profinfo;
	net_profile_name_t PdpProfName;

	PdpProfName.ProfileName[0] = '\0';

	__net_telephony_init_profile_info(&telephony_profinfo);

	/* Find matching profile in telephony service */
	Error = __net_telephony_search_pdp_profile(ProfInfo->ProfileName, &PdpProfName);

	if (Error == NET_ERR_NONE && strlen(PdpProfName.ProfileName) > 0) {
		/* Get profile info from telephony service */
		Error = __net_telephony_get_profile_info(&PdpProfName, &telephony_profinfo);

		if (Error == NET_ERR_NONE) {
			ProfInfo->ProfileInfo.Pdp.ServiceType = telephony_profinfo.ServiceType;

			if (strlen(telephony_profinfo.Apn) > 0)
				g_strlcpy(ProfInfo->ProfileInfo.Pdp.Apn,
						telephony_profinfo.Apn, NET_PDP_APN_LEN_MAX);

			if (strlen(telephony_profinfo.ProxyAddr) > 0)
				g_strlcpy(ProfInfo->ProfileInfo.Pdp.net_info.ProxyAddr,
						telephony_profinfo.ProxyAddr, NET_PROXY_LEN_MAX);

			if (strlen(telephony_profinfo.HomeURL) > 0)
				g_strlcpy(ProfInfo->ProfileInfo.Pdp.HomeURL,
						telephony_profinfo.HomeURL, NET_HOME_URL_LEN_MAX);

			ProfInfo->ProfileInfo.Pdp.AuthInfo.AuthType = telephony_profinfo.AuthInfo.AuthType;

			if (strlen(telephony_profinfo.AuthInfo.UserName) > 0)
				g_strlcpy(ProfInfo->ProfileInfo.Pdp.AuthInfo.UserName,
						telephony_profinfo.AuthInfo.UserName,
						NET_PDP_AUTH_USERNAME_LEN_MAX);

			if (strlen(telephony_profinfo.AuthInfo.Password) > 0)
				g_strlcpy(ProfInfo->ProfileInfo.Pdp.AuthInfo.Password,
						telephony_profinfo.AuthInfo.Password,
						NET_PDP_AUTH_PASSWORD_LEN_MAX);
		}
	}

	__NETWORK_FUNC_EXIT__;

	return Error;
}

static int __net_extract_service_info(const char* ProfileName, DBusMessage *message, net_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusMessageIter iter, array;
	net_device_t profileType = NET_DEVICE_UNKNOWN;

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	while (dbus_message_iter_get_arg_type(&array) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter entry, dict;
		const char *key = NULL;
		const char *temp = NULL;

		dbus_message_iter_recurse(&array, &entry);
		dbus_message_iter_get_basic(&entry, &key);		

		if (strcmp(key, "Type") == 0) {
			dbus_message_iter_next(&entry);
			dbus_message_iter_recurse(&entry, &dict);
			dbus_message_iter_get_basic(&dict, &temp);
			if (strcmp(temp, "wifi") == 0)
				profileType = NET_DEVICE_WIFI;
			else if (strcmp(temp, "cellular") == 0)
				profileType = NET_DEVICE_CELLULAR;

			break;
		}

		dbus_message_iter_next(&array);
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &array);

	if (profileType == NET_DEVICE_WIFI) {
		if ((Error = __net_pm_init_profile_info(NET_DEVICE_WIFI, ProfInfo)) != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't init profile\n");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
		
		ProfInfo->profile_type = NET_DEVICE_WIFI;
		g_strlcpy(ProfInfo->ProfileName, ProfileName, NET_PROFILE_NAME_LEN_MAX);
		g_strlcpy(ProfInfo->ProfileInfo.Wlan.net_info.ProfileName,
				ProfileName, NET_PROFILE_NAME_LEN_MAX);

		Error = __net_extract_wifi_info(&array, ProfInfo);

	} else if (profileType == NET_DEVICE_CELLULAR) {
		if ((Error = __net_pm_init_profile_info(NET_DEVICE_CELLULAR, ProfInfo)) != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't init profile\n");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
		
		ProfInfo->profile_type = NET_DEVICE_CELLULAR;
		g_strlcpy(ProfInfo->ProfileName, ProfileName, NET_PROFILE_NAME_LEN_MAX);
		g_strlcpy(ProfInfo->ProfileInfo.Pdp.net_info.ProfileName,
				ProfileName, NET_PROFILE_NAME_LEN_MAX);
		
		Error = __net_extract_mobile_info(&array, ProfInfo);
	} else {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Not supported profile type\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NOT_SUPPORTED;
	}		

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Can't extract service information from received message\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;

	return Error;	
}

static int __net_get_profile_info(const char* ProfileName, net_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, conn, ProfileName,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to get service(profile) information\n");
		goto done;
	}

	Error = __net_extract_service_info(ProfileName, message, ProfInfo);

	dbus_message_unref(message); 
done:
	dbus_connection_unref(conn); 

	__NETWORK_FUNC_EXIT__;

	return Error;
}


static int __net_set_profile_property(char* path, char* key, char* value)
{
	__NETWORK_FUNC_ENTER__;
	
	net_err_t Error = NET_ERR_NONE;

	char request[] = CONNMAN_SERVICE_INTERFACE ".SetProperty";
	char* param_array[] = {NULL, NULL, NULL, NULL, NULL};
	
	param_array[0] = path;
	param_array[1] = request;
	param_array[2] = key;
	param_array[3] = value;

	NETWORK_LOG(NETWORK_HIGH,  "Requesting [%s %s %s %s]\n",
		param_array[0],
		param_array[1],
		param_array[2],
		param_array[3]);
	
	Error = _net_send_dbus_request(CONNMAN_SERVICE, param_array, NULL);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,  "Error!!! _net_send_dbus_request failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_modify_wlan_profile_info(const char* ProfileName,
		net_profile_info_t* ProfInfo, net_profile_info_t* exProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	int i = 0;
	char profilePath[NET_PROFILE_NAME_LEN_MAX+1] = "";
	char propertyInfo[128] = "";
	char keyString[64] = "";

	wlan_security_info_t *security_info = &(ProfInfo->ProfileInfo.Wlan.security_info);
	wlan_security_info_t *ex_security_info = &(exProfInfo->ProfileInfo.Wlan.security_info);

	net_dev_info_t *net_info = &(ProfInfo->ProfileInfo.Wlan.net_info);
	net_dev_info_t *ex_net_info = &(exProfInfo->ProfileInfo.Wlan.net_info);

	snprintf(profilePath, NET_PROFILE_NAME_LEN_MAX+1, "%s", ProfileName);

	/* Compare and Set 'Passphrase' */
	if (ex_security_info->sec_mode == WLAN_SEC_MODE_WEP) {
		if (strcmp(security_info->authentication.wep.wepKey
			, ex_security_info->authentication.wep.wepKey) != 0) {

			snprintf(keyString, 64, "string:Passphrase");
			snprintf(propertyInfo, 128, "variant:string:%s",
					security_info->authentication.wep.wepKey);
			Error = __net_set_profile_property(profilePath, keyString, propertyInfo);
			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR,
						"Error!!! __net_set_profile_property() failed\n");
				__NETWORK_FUNC_EXIT__;
				return Error;
			}
		}
	} else if (ex_security_info->sec_mode == WLAN_SEC_MODE_WPA_PSK ||
	           ex_security_info->sec_mode == WLAN_SEC_MODE_WPA2_PSK) {

		if (strcmp(security_info->authentication.psk.pskKey,
		           ex_security_info->authentication.psk.pskKey) != 0) {

			snprintf(keyString, 64, "string:Passphrase");
			snprintf(propertyInfo, 128, "variant:string:%s",
					security_info->authentication.psk.pskKey);
			Error = __net_set_profile_property(profilePath, keyString, propertyInfo);
			
			if (Error != NET_ERR_NONE) {
				__NETWORK_FUNC_EXIT__;
				return Error;
			}
		}
	}

	/* Compare and Set 'Proxy' */
	if ((ex_net_info->ProxyMethod != net_info->ProxyMethod) ||
	    (strcmp(ex_net_info->ProxyAddr, net_info->ProxyAddr) != 0)) {

		Error = _net_dbus_set_proxy(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	/* Compare and Set 'IPv4 addresses' */
	if ((ex_net_info->IpConfigType != net_info->IpConfigType) ||
	    (net_info->IpConfigType == NET_IP_CONFIG_TYPE_STATIC &&
	     (net_info->IpAddr.Data.Ipv4.s_addr != ex_net_info->IpAddr.Data.Ipv4.s_addr ||
	      net_info->SubnetMask.Data.Ipv4.s_addr != ex_net_info->SubnetMask.Data.Ipv4.s_addr ||
	      net_info->GatewayAddr.Data.Ipv4.s_addr != ex_net_info->GatewayAddr.Data.Ipv4.s_addr))) {

		Error = _net_dbus_set_profile_ipv4(ProfInfo, profilePath);
		
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,  "Error!!! Can't set IPv4\n");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	/* Compare and Set 'DNS addresses' */
	if (net_info->IpConfigType == NET_IP_CONFIG_TYPE_STATIC) {
		for (i = 0;i < net_info->DnsCount;i++) {
			if(i >= NET_DNS_ADDR_MAX) {
				net_info->DnsCount = NET_DNS_ADDR_MAX;
				break;
			}

			if (net_info->DnsAddr[i].Data.Ipv4.s_addr !=
			    ex_net_info->DnsAddr[i].Data.Ipv4.s_addr) break;
		}

		if (i < net_info->DnsCount) {
			Error = _net_dbus_set_profile_dns(ProfInfo, profilePath);

			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR,  "Error!!! Can't set dns\n");
				__NETWORK_FUNC_EXIT__;
				return Error;
			}
		}
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_wifi_delete_profile(net_profile_name_t* WifiProfName)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, conn, WifiProfName->ProfileName,
			CONNMAN_SERVICE_INTERFACE, "Remove", &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to Remove service(profile)\n");
		goto done;
	}

	dbus_message_unref(message);
done:
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}


static int __net_telephony_add_profile(net_profile_info_t *ProfInfo, net_service_type_t network_type)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	ProfInfo->ProfileInfo.Pdp.ServiceType = network_type;

	Error = _net_dbus_add_pdp_profile(ProfInfo);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_HIGH, "_net_dbus_add_pdp_profile() failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_telephony_modify_profile(const char *ProfileName,
		net_profile_info_t *ProfInfo, net_profile_info_t* exProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t telephony_profile;
	char connman_profile[NET_PROFILE_NAME_LEN_MAX+1] = "";

	g_strlcpy(connman_profile, ProfileName, NET_PROFILE_NAME_LEN_MAX+1);
	ProfInfo->ProfileInfo.Pdp.ServiceType = exProfInfo->ProfileInfo.Pdp.ServiceType;

	Error = __net_telephony_search_pdp_profile((char*)connman_profile, &telephony_profile);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_HIGH, "__net_telephony_search_pdp_profile() failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = _net_dbus_modify_pdp_profile(ProfInfo, (char*)telephony_profile.ProfileName);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_HIGH, "_net_dbus_modify_pdp_profile() failed\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;

	return Error;
}

static int __net_telephony_delete_profile(net_profile_name_t* PdpProfName)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);

	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = _net_invoke_dbus_method(TELEPHONY_SERVCE, conn, PdpProfName->ProfileName,
			TELEPHONY_PROFILE_INTERFACE, "RemoveProfile", &Error);

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to Remove service(profile)\n");
		goto done;
	}

	/** Check Reply */
	DBusMessageIter iter;
	int remove_result = 0;

	dbus_message_iter_init(message, &iter);
	if (dbus_message_iter_get_arg_type(&iter) == DBUS_TYPE_BOOLEAN) {
		dbus_message_iter_get_basic(&iter, &remove_result);
		NETWORK_LOG(NETWORK_HIGH, "Profile remove result : %d\n", remove_result);
	}

	if (remove_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	dbus_message_unref(message);

done:
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_defult_device(DBusMessageIter* dict, net_device_t *device_type)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	if (dict == NULL || device_type == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid prarameter \n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	*device_type = NET_DEVICE_UNKNOWN;

	while (dbus_message_iter_get_arg_type(dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter keyValue, value;
		const char *key = NULL;
		const char *objPath = NULL;

		dbus_message_iter_recurse(dict, &keyValue);
		dbus_message_iter_get_basic(&keyValue, &key);

		if (strcmp(key, "DefaultTechnology") == 0) {
			dbus_message_iter_next(&keyValue);
			dbus_message_iter_recurse(&keyValue, &value);

			if (dbus_message_iter_get_arg_type(&value) != DBUS_TYPE_STRING)
				break;

			dbus_message_iter_get_basic(&value, &objPath);
			if (objPath == NULL || strlen(objPath) == 0)
				break;

			if (strcmp(objPath, "wifi") == 0)
				*device_type = NET_DEVICE_WIFI;
			else if (strcmp(objPath, "cellular") == 0)
				*device_type = NET_DEVICE_CELLULAR;

			break;
		}
		dbus_message_iter_next(dict);
	}

	if (*device_type == NET_DEVICE_UNKNOWN)
		Error = NET_ERR_NO_SERVICE;

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_defult_profile(DBusMessageIter* iter, net_profile_name_t *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_device_t device_type = NET_DEVICE_UNKNOWN;
	DBusMessageIter dict;
	const char net_suffix[] = "_1";
	char *suffix = NULL;
	const char *objPath = NULL;

	if (iter == NULL || profile_name == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid prarameter \n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	memset(profile_name, 0, sizeof(net_profile_name_t));

	dbus_message_iter_recurse(iter, &dict);
	Error = __net_extract_defult_device(&dict, &device_type);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! There is no Default Technology\n");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	dbus_message_iter_recurse(iter, &dict);
	while (dbus_message_iter_get_arg_type(&dict) == DBUS_TYPE_DICT_ENTRY) {
		DBusMessageIter keyValue, array, value;
		const char *key = NULL;

		dbus_message_iter_recurse(&dict, &keyValue);
		dbus_message_iter_get_basic(&keyValue, &key);

		if (strcmp(key, "Services") == 0) {
			dbus_message_iter_next(&keyValue);
			dbus_message_iter_recurse(&keyValue, &array);

			if (dbus_message_iter_get_arg_type(&array) != DBUS_TYPE_ARRAY) {
				NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't get service list\n");
				__NETWORK_FUNC_EXIT__;
				return NET_ERR_NO_SERVICE;
			}

			dbus_message_iter_recurse(&array, &value);

			while (dbus_message_iter_get_arg_type(&value) == DBUS_TYPE_OBJECT_PATH) {
				dbus_message_iter_get_basic(&value, &objPath);

				if (device_type == NET_DEVICE_CELLULAR &&
				    strstr(objPath, "/cellular_") != NULL) {

					suffix = strrchr(objPath, '_');

					if (strcmp(suffix, net_suffix) == 0) {
						goto found;
					}

				} else if (device_type == NET_DEVICE_WIFI &&
				           strstr(objPath, "/wifi_") != NULL)
					goto found;
				else
					break;

				dbus_message_iter_next(&value);
			}
			NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't find default service\n");
			__NETWORK_FUNC_EXIT__;
			return NET_ERR_NO_SERVICE;
		}
		dbus_message_iter_next(&dict);
	}

	NETWORK_LOG(NETWORK_EXCEPTION, "Error!!! Can't find default service\n");
	Error = NET_ERR_NO_SERVICE;

found:
	if (Error == NET_ERR_NONE && objPath != NULL) {
		g_strlcpy(profile_name->ProfileName, objPath, NET_PROFILE_NAME_LEN_MAX);
		NETWORK_LOG(NETWORK_HIGH, "Default profile found : %s\n", profile_name->ProfileName);
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}


int _net_check_profile_name(const char* ProfileName)
{
	__NETWORK_FUNC_ENTER__;

	const char *profileHeader = CONNMAN_PATH"/service/";
	int i = 0;
	int stringLen = 0;

	if (ProfileName == NULL || strlen(ProfileName) <= strlen(profileHeader)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Profile name is invalid\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	stringLen = strlen(ProfileName);

	if (strncmp(profileHeader, ProfileName, strlen(profileHeader)) == 0) {
		for (i = 0;i < stringLen;i++) {
			if (isgraph(ProfileName[i]) == 0) {
				NETWORK_LOG(NETWORK_ERROR, "Error!!! Profile name is invalid\n");
				__NETWORK_FUNC_EXIT__;
				return NET_ERR_INVALID_PARAM;
			}
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Profile name is invalid\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_get_profile_list(net_device_t device_type, net_profile_info_t** profile_info, int* profile_count)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL); 
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, conn, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetProperties", &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to get service(profile) list\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	switch (device_type) {
	case NET_DEVICE_CELLULAR:
	case NET_DEVICE_WIFI:
		Error = __net_extract_services(message, device_type, profile_info, profile_count);
		break;
	default :
		Error = NET_ERR_UNKNOWN;
		break;
	}

	NETWORK_LOG(NETWORK_HIGH, "Error = %d\n", Error);

	dbus_message_unref(message); 
	dbus_connection_unref(conn); 

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_get_service_profile(net_service_type_t service_type, net_profile_name_t *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter, dict;
	network_services_list_t service_info = {0,};
	int i = 0;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, conn, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetProperties", &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to get service(profile) list\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	dbus_message_iter_init(message, &iter);
	dbus_message_iter_recurse(&iter, &dict);

	Error = __net_extract_mobile_services(message, &dict, &service_info, service_type);

	if (Error != NET_ERR_NONE)
		goto done;

	if (service_info.num_of_services > 0) {
		memcpy(profile_name->ProfileName, service_info.ProfileName[0], NET_PROFILE_NAME_LEN_MAX);
		(profile_name->ProfileName)[NET_PROFILE_NAME_LEN_MAX] = '\0';
	} else
		Error = NET_ERR_NO_SERVICE;

	for (i = 0;i < service_info.num_of_services;i++)
		NET_MEMFREE(service_info.ProfileName[i]);

done:
	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_get_default_profile_info(net_profile_info_t *profile_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	DBusConnection* conn = NULL;
	DBusMessage *message = NULL;
	DBusMessageIter iter;
	net_profile_name_t profile_name;
	const char *prof_name = NULL;

	conn = dbus_bus_get(DBUS_BUS_SYSTEM, NULL);
	if (conn == NULL) {
		NETWORK_LOG(NETWORK_EXCEPTION,
				"Error!!! Can't get on system bus\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_UNKNOWN;
	}

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, conn, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetProperties", &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! Failed to get service(profile) list\n");
		dbus_connection_unref(conn);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	dbus_message_iter_init(message, &iter);
	Error = __net_extract_defult_profile(&iter, &profile_name);

	if (Error != NET_ERR_NONE)
		goto done;

	prof_name = (const char*)profile_name.ProfileName;
	Error = __net_get_profile_info(prof_name, profile_info);

done:
	dbus_message_unref(message);
	dbus_connection_unref(conn);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Sync API Definition
 *****************************************************************************/


EXPORT_API int net_add_profile(net_service_type_t network_type, net_profile_info_t *prof_info)
{
	net_err_t Error = NET_ERR_NONE;
	
	__NETWORK_FUNC_ENTER__;
	
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (prof_info == NULL ||
		(network_type != NET_SERVICE_INTERNET &&
		network_type != NET_SERVICE_MMS &&
		network_type != NET_SERVICE_WAP)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_telephony_add_profile(prof_info, network_type);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! failed to add service(profile). Error [%s]\n",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;	
	return Error;
}


EXPORT_API int net_delete_profile(const char* profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t pdp_prof_name;
	net_profile_name_t wifi_prof_name;
	net_profile_info_t prof_info;
	
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_get_profile_info(profile_name, &prof_info);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! failed to get service(profile) information. Error [%s]\n",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_strlcpy(wifi_prof_name.ProfileName, profile_name, NET_PROFILE_NAME_LEN_MAX + 1);

	if (prof_info.profile_type == NET_DEVICE_WIFI) {
		Error = __net_wifi_delete_profile(&wifi_prof_name);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Error!!! failed to delete service(profile). Error [%s]\n",
					_net_print_error(Error));
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	} else if (prof_info.profile_type == NET_DEVICE_CELLULAR) {
		Error = __net_telephony_search_pdp_profile(wifi_prof_name.ProfileName, &pdp_prof_name);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Error!!! failed to get service(profile) information. Error [%s]\n",
					_net_print_error(Error));
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		Error = __net_telephony_delete_profile(&pdp_prof_name);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Error!!! failed to delete service(profile). Error [%s]\n",
					_net_print_error(Error));
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;
}


EXPORT_API int net_get_profile_info(const char *profile_name, net_profile_info_t *prof_info)
{
	__NETWORK_FUNC_ENTER__;
	
	net_err_t Error = NET_ERR_NONE;
	
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE || prof_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}	

	Error = __net_get_profile_info(profile_name, prof_info);
	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR,
			"Error!!! failed to get service(profile) information. Error [%s]\n",
			_net_print_error(Error));
	
	__NETWORK_FUNC_EXIT__;
	return Error;
}


EXPORT_API int net_modify_profile(const char* profile_name, net_profile_info_t* prof_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t exProfInfo;
	
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}	

	Error = net_get_profile_info(profile_name, &exProfInfo);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! failed to get service(profile) information. Error [%s]\n",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (prof_info == NULL ||
	    (exProfInfo.profile_type != NET_DEVICE_WIFI &&
	     exProfInfo.profile_type != NET_DEVICE_CELLULAR)) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (exProfInfo.profile_type == NET_DEVICE_WIFI)
		Error = __net_modify_wlan_profile_info(profile_name, prof_info, &exProfInfo);
	else if (exProfInfo.profile_type == NET_DEVICE_CELLULAR)
		Error = __net_telephony_modify_profile(profile_name, prof_info, &exProfInfo);
	
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! failed to modify service(profile) information. Error [%s]\n",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}
	
	__NETWORK_FUNC_EXIT__;	

	return NET_ERR_NONE;
}


EXPORT_API int net_get_profile_list(net_device_t device_type, net_profile_info_t **profile_list, int *count)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	int profile_count = 0;
	net_profile_info_t* profile_info = NULL;

	if (count == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}
	
	if (NetworkInfo.ClientEventCb == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application was not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}	

	if (device_type != NET_DEVICE_CELLULAR && device_type != NET_DEVICE_WIFI) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Not Supported\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NOT_SUPPORTED;
	}
	
	Error = _net_get_profile_list(device_type, &profile_info, &profile_count);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Error!!! failed to get service(profile) list. Error [%s]\n",
				_net_print_error(Error));
		
		NET_MEMFREE(profile_info);
		
		__NETWORK_FUNC_EXIT__;
		return Error;
	} else {
		*count = profile_count;
		*profile_list = profile_info;
	}
	
	__NETWORK_FUNC_EXIT__;	
	return NET_ERR_NONE;	
}


/*****************************************************************************
 * 	ConnMan Wi-Fi Client Interface Async Function Definition
 *****************************************************************************/

#ifdef __cplusplus
}
#endif /* __cplusplus */

