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

#include <ctype.h>
#include <stdio.h>
#include <arpa/inet.h>

#include "network-internal.h"
#include "network-dbus-request.h"

#define DBUS_OBJECT_PATH_MAX	150

/*****************************************************************************
 * 	Local Functions Declaration
 *****************************************************************************/
static int __net_extract_wifi_info(GVariantIter *array, net_profile_info_t* ProfInfo);
static int __net_extract_service_info(const char* ProfileName,
		GVariant *message, net_profile_info_t* ProfInfo);
static int __net_extract_services(GVariantIter *message, net_device_t device_type,
		net_profile_info_t** profile_info, int* profile_count);
static int __net_extract_ip(const gchar *value, net_addr_t *ipAddr);
static int __net_extract_common_info(const char *key, GVariant *variant, net_profile_info_t* ProfInfo);
static int __net_extract_mobile_info(GVariantIter *array, net_profile_info_t* ProfInfo);
static int __net_extract_ethernet_info(GVariantIter *array, net_profile_info_t* ProfInfo);
static int __net_extract_bluetooth_info(GVariantIter *array, net_profile_info_t* ProfInfo);

/*****************************************************************************
 * Extern Variables
 *****************************************************************************/
extern __thread network_info_t NetworkInfo;
extern __thread network_request_table_t request_table[NETWORK_REQUEST_TYPE_MAX];

/*****************************************************************************
 * 	Local Functions Definition
 *****************************************************************************/
static int __net_pm_init_profile_info(net_device_t profile_type, net_profile_info_t *ProfInfo)
{
	int i = 0;
	net_dev_info_t *net_info = NULL;

	if (ProfInfo == NULL ||
	   (profile_type != NET_DEVICE_WIFI &&
	    profile_type != NET_DEVICE_CELLULAR &&
	    profile_type != NET_DEVICE_ETHERNET &&
	    profile_type != NET_DEVICE_BLUETOOTH)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter\n");
		return NET_ERR_INVALID_PARAM;
	}

	memset(ProfInfo, 0, sizeof(net_profile_info_t));
	ProfInfo->Favourite = (char)FALSE;

	if (profile_type == NET_DEVICE_WIFI) {
		ProfInfo->profile_type = NET_DEVICE_WIFI;
		ProfInfo->ProfileInfo.Wlan.Strength = 0;
		ProfInfo->ProfileInfo.Wlan.frequency = 0;
		ProfInfo->ProfileInfo.Wlan.max_rate = 0;
		ProfInfo->ProfileInfo.Wlan.wlan_mode = 0;
		ProfInfo->ProfileInfo.Wlan.PassphraseRequired = FALSE;
		ProfInfo->ProfileInfo.Wlan.security_info.sec_mode = 0;
		ProfInfo->ProfileInfo.Wlan.security_info.enc_mode = 0;
		ProfInfo->ProfileInfo.Wlan.security_info.wps_support = FALSE;

		net_info = &(ProfInfo->ProfileInfo.Wlan.net_info);
	} else if (profile_type == NET_DEVICE_CELLULAR) {
		ProfInfo->profile_type = NET_DEVICE_CELLULAR;
		ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_NONE;
		ProfInfo->ProfileInfo.Pdp.ServiceType = NET_SERVICE_UNKNOWN;
		ProfInfo->ProfileInfo.Pdp.AuthInfo.AuthType = NET_PDP_AUTH_NONE;
		ProfInfo->ProfileInfo.Pdp.IsStatic = FALSE;
		ProfInfo->ProfileInfo.Pdp.Roaming = FALSE;
		ProfInfo->ProfileInfo.Pdp.SetupRequired = FALSE;
		ProfInfo->ProfileInfo.Pdp.Hidden = FALSE;
		ProfInfo->ProfileInfo.Pdp.Editable = TRUE;
		ProfInfo->ProfileInfo.Pdp.DefaultConn = FALSE;

		net_info = &(ProfInfo->ProfileInfo.Pdp.net_info);
	} else if (profile_type == NET_DEVICE_ETHERNET) {
		net_info = &(ProfInfo->ProfileInfo.Ethernet.net_info);
	} else if (profile_type == NET_DEVICE_BLUETOOTH) {
		net_info = &(ProfInfo->ProfileInfo.Bluetooth.net_info);
	}

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

	net_info->IpConfigType6 = 0;
	net_info->IpAddr6.Type = NET_ADDR_IPV6;
	inet_pton(AF_INET6, "::", &net_info->IpAddr6.Data.Ipv6);
	net_info->PrefixLen6 = 0;
	net_info->BDefGateway6 = FALSE;
	net_info->GatewayAddr6.Type = NET_ADDR_IPV6;
	inet_pton(AF_INET6, "::", &net_info->GatewayAddr6.Data.Ipv6);

	net_info->ProxyMethod = NET_PROXY_TYPE_UNKNOWN;

	return NET_ERR_NONE;
}

static int __net_telephony_init_profile_info(net_telephony_profile_info_t* ProfInfo)
{
	if (ProfInfo == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");

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

	memset(ProfInfo->Keyword, '\0', NET_PDP_APN_LEN_MAX+1);
	ProfInfo->Hidden = FALSE;
	ProfInfo->Editable = TRUE;
	ProfInfo->DefaultConn = FALSE;

	return NET_ERR_NONE;
}

static int __net_telephony_get_profile_info(net_profile_name_t* ProfileName, net_telephony_profile_info_t *ProfileInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *result;
	GVariantIter *iter;
	const gchar *key = NULL;
	const gchar *value = NULL;

	if (ProfileName == NULL || ProfileInfo == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter!");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	result = _net_invoke_dbus_method(TELEPHONY_SERVICE, ProfileName->ProfileName,
			TELEPHONY_PROFILE_INTERFACE, "GetProfile", NULL, &Error);
	if (result == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "_net_invoke_dbus_method failed");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = __net_telephony_init_profile_info(ProfileInfo);

	if (Error != NET_ERR_NONE) {
		g_variant_unref(result);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(result, "(a{ss})", &iter);
	while (g_variant_iter_next(iter, "{ss}", &key, &value)) {
		if (g_strcmp0(key, "path") == 0) {
			if (value != NULL)
				g_strlcpy(ProfileInfo->ProfileName, value, NET_PROFILE_NAME_LEN_MAX);
		} else if (g_strcmp0(key, "svc_ctg_id") == 0) {
			net_service_type_t ServiceType = NET_SERVICE_UNKNOWN;

			if (value != NULL)
				ServiceType = atoi(value);

			if (ServiceType > NET_SERVICE_UNKNOWN)
				ProfileInfo->ServiceType = ServiceType;
		} else if (g_strcmp0(key, "apn") == 0) {
			if (value != NULL)
				g_strlcpy(ProfileInfo->Apn, value, NET_PDP_APN_LEN_MAX);
		} else if (g_strcmp0(key, "auth_type") == 0) {
			net_auth_type_t authType = NET_PDP_AUTH_NONE;

			if (value != NULL)
				authType = atoi(value);

			if (authType == NET_PDP_AUTH_PAP)
				ProfileInfo->AuthInfo.AuthType = NET_PDP_AUTH_PAP;
			else if (authType == NET_PDP_AUTH_CHAP)
				ProfileInfo->AuthInfo.AuthType = NET_PDP_AUTH_CHAP;
		} else if (g_strcmp0(key, "auth_id") == 0) {
			if (value != NULL)
				g_strlcpy(ProfileInfo->AuthInfo.UserName, value, NET_PDP_AUTH_USERNAME_LEN_MAX);
		} else if (g_strcmp0(key, "auth_pwd") == 0) {
			if (value != NULL)
				g_strlcpy(ProfileInfo->AuthInfo.Password, value, NET_PDP_AUTH_PASSWORD_LEN_MAX);
		} else if (g_strcmp0(key, "proxy_addr") == 0) {
			if (value != NULL)
				g_strlcpy(ProfileInfo->ProxyAddr, value, NET_PROXY_LEN_MAX);
		} else if (g_strcmp0(key, "home_url") == 0) {
			if (value != NULL)
				g_strlcpy(ProfileInfo->HomeURL, value, NET_HOME_URL_LEN_MAX);
		} else if (g_strcmp0(key, "default_internet_conn") == 0) {
			if (value == NULL)
				continue;

			if (g_strcmp0(value, "TRUE") == 0)
				ProfileInfo->DefaultConn = TRUE;
			else
				ProfileInfo->DefaultConn = FALSE;
		} else if (g_strcmp0(key, "profile_name") == 0) {
			if (value != NULL)
				g_strlcpy(ProfileInfo->Keyword, value, NET_PDP_APN_LEN_MAX);
		} else if (g_strcmp0(key, "editable") == 0) {
			if (value == NULL)
				continue;

			if (g_strcmp0(value, "TRUE") == 0)
				ProfileInfo->Editable = TRUE;
			else
				ProfileInfo->Editable = FALSE;
		} else if (g_strcmp0(key, "hidden") == 0) {
			if (value == NULL)
				continue;

			if (g_strcmp0(value, "TRUE") == 0)
				ProfileInfo->Hidden = TRUE;
			else
				ProfileInfo->Hidden = FALSE;
		}
	}

	g_variant_iter_free(iter);
	g_variant_unref(result);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_telephony_get_modem_object_path(GSList **ModemPathList)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *result;
	GVariantIter *iter_modem = NULL;
	GVariantIter *modem_properties = NULL;
	const char *modem_path;

	result = _net_invoke_dbus_method(TELEPHONY_SERVICE, TELEPHONY_MASTER_PATH,
			TELEPHONY_MASTER_INTERFACE, "GetModems", NULL, &Error);
	if (result == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get modem path list");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(result, "(a{sa{ss}})", &iter_modem);
	while (g_variant_iter_loop(iter_modem, "{sa{ss}}", &modem_path, &modem_properties)) {
		*ModemPathList = g_slist_append(*ModemPathList, g_strdup(modem_path));
		NETWORK_LOG(NETWORK_LOW, "modem object path: %s",	modem_path);
	}

	g_variant_iter_free(iter_modem);
	g_variant_unref(result);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_telephony_get_profile_list(net_profile_name_t **ProfileName,
		int *ProfileCount)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	int count = 0, i = 0;
	const char *str = NULL;
	GVariant *result;
	GVariantIter *iter = NULL;
	GSList *profiles = NULL, *list = NULL;
	net_profile_name_t *profileList = NULL;

	GSList *ModemPathList = NULL;
	const char *path = NULL;

	Error = __net_telephony_get_modem_object_path(&ModemPathList);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get modems path list");

		g_slist_free_full(ModemPathList, g_free);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	for (list = ModemPathList; list != NULL; list = list->next) {
		path = (const char *)list->data;

		NETWORK_LOG(NETWORK_LOW, "path: %s", path);
		result = _net_invoke_dbus_method(TELEPHONY_SERVICE, path,
				TELEPHONY_MODEM_INTERFACE, "GetProfileList", NULL, &Error);
		if (result == NULL) {
			NETWORK_LOG(NETWORK_LOW, "Failed to get profiles: %s", path);
			continue;
		}

		g_variant_get(result, "(as)", &iter);
		while (g_variant_iter_loop(iter, "s", &str))
			profiles = g_slist_append(profiles, g_strdup(str));

		g_variant_iter_free(iter);
		g_variant_unref(result);
	}

	g_slist_free_full(ModemPathList, g_free);

	count = g_slist_length(profiles);
	if (count > 0) {
		profileList = (net_profile_name_t*)malloc(sizeof(net_profile_name_t) * count);
		Error = NET_ERR_NONE;
	} else {
		*ProfileCount = 0;
		goto out;
	}

	if (profileList == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to allocate memory");
		*ProfileCount = 0;
		Error = NET_ERR_UNKNOWN;
		goto out;
	}

	for (list = profiles, i = 0; list != NULL; list = list->next, i++)
		g_strlcpy(profileList[i].ProfileName,
				(const char *)list->data, NET_PROFILE_NAME_LEN_MAX);

	*ProfileName = profileList;
	*ProfileCount = count;

out:
	g_slist_free_full(profiles, g_free);

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
		NETWORK_LOG(NETWORK_ERROR, "Failed to get profile list from telephony service");
		NET_MEMFREE(ProfileList);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (ProfileList == NULL || ProfileCount <= 0) {
		NETWORK_LOG(NETWORK_ERROR, "There is no PDP profiles");
		NET_MEMFREE(ProfileList);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NO_SERVICE;
	}

	/* Find matching profile */
	connmanProfName = strrchr(ProfileName, '/') + 1;
	for (i = 0; i < ProfileCount; i++) {
		telephonyProfName = strrchr(ProfileList[i].ProfileName, '/') + 1;
		foundPtr = strstr(connmanProfName, telephonyProfName);

		if (foundPtr != NULL && g_strcmp0(foundPtr, telephonyProfName) == 0) {
			g_strlcpy(PdpProfName->ProfileName,
					ProfileList[i].ProfileName, NET_PROFILE_NAME_LEN_MAX);

			NETWORK_LOG(NETWORK_HIGH,
					"PDP profile name found in cellular profile: %s",
					PdpProfName->ProfileName);
			break;
		}
	}

	if (i >= ProfileCount) {
		NETWORK_LOG(NETWORK_ERROR, "There is no matching PDP profiles");
		NET_MEMFREE(ProfileList);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NO_SERVICE;
	}

	NET_MEMFREE(ProfileList);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_mobile_services(GVariantIter *iter,
		network_services_list_t *service_info,
		net_service_type_t network_type)
{
	int count = 0, i = 0;
	const char net_suffix[] = "_1";
	const char mms_suffix[] = "_2";
	const char pre_net_suffix[] = "_3";
	const char pre_mms_suffix[] = "_4";
	const char tethering_suffix[] = "_5";
	char *suffix = NULL;
	gchar *obj = NULL;
	GVariantIter *value = NULL;
	gboolean found = FALSE;

	__NETWORK_FUNC_ENTER__;

	if (iter == NULL || service_info == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NET_SERVICE_INTERNET <= network_type &&
			network_type <= NET_SERVICE_TETHERING) {
		NETWORK_LOG(NETWORK_ERROR, "Service type %d", network_type);
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid service type %d", network_type);
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	service_info->num_of_services = 0;

	while (g_variant_iter_loop(iter, "(oa{sv})", &obj, &value)) {
		if (obj == NULL)
			continue;

		if (g_str_has_prefix(obj,
				CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX) == TRUE) {
			found = FALSE;

			suffix = strrchr(obj, '_');

			if (network_type == NET_SERVICE_INTERNET &&
					g_strcmp0(suffix, net_suffix) == 0)
				found = TRUE;
			else if (network_type == NET_SERVICE_MMS &&
					g_strcmp0(suffix, mms_suffix) == 0)
				found = TRUE;
			else if (network_type == NET_SERVICE_PREPAID_INTERNET &&
					g_strcmp0(suffix, pre_net_suffix) == 0)
				found = TRUE;
			else if (network_type == NET_SERVICE_PREPAID_MMS &&
					g_strcmp0(suffix, pre_mms_suffix) == 0)
				found = TRUE;
			else if (network_type == NET_SERVICE_TETHERING &&
					g_strcmp0(suffix, tethering_suffix) == 0)
				found = TRUE;

			if (found == TRUE) {
				service_info->ProfileName[count] =
						(char*)malloc(NET_PROFILE_NAME_LEN_MAX+1);
				if (service_info->ProfileName[count] == NULL) {
					NETWORK_LOG(NETWORK_ERROR, "Failed to allocate memory");

					for (i = 0; i < count; i++)
						NET_MEMFREE(service_info->ProfileName[i]);

					g_variant_iter_free(value);
					g_free(obj);

					__NETWORK_FUNC_EXIT__;
					return NET_ERR_UNKNOWN;
				}

				g_strlcpy(service_info->ProfileName[count], obj,
						NET_PROFILE_NAME_LEN_MAX+1);

				count++;
			}
		}
	}

	service_info->num_of_services = count;

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_extract_all_services(GVariantIter *array,
		net_device_t device_type, const char *service_prefix,
		int *prof_count, net_profile_info_t **ProfilePtr)
{
	int count = 0;
	net_profile_info_t ProfInfo = { 0, };
	net_err_t Error = NET_ERR_NONE;
	gchar *obj;
	GVariantIter *next = NULL;

	__NETWORK_FUNC_ENTER__;

	if (array == NULL || service_prefix == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	while (g_variant_iter_loop(array, "(oa{sv})", &obj, &next)) {
		if (obj == NULL)
			continue;

		if (g_str_has_prefix(obj, service_prefix) == TRUE) {
			memset(&ProfInfo, 0, sizeof(net_profile_info_t));

			if ((Error = __net_pm_init_profile_info(device_type, &ProfInfo)) != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR, "Failed to init profile");

				NET_MEMFREE(*ProfilePtr);
				*prof_count = 0;

				goto error;
			}

			if (device_type == NET_DEVICE_WIFI &&
					g_strrstr(obj + strlen(service_prefix), "hidden") != NULL)
				ProfInfo.ProfileInfo.Wlan.is_hidden = TRUE;

			ProfInfo.profile_type = device_type;
			g_strlcpy(ProfInfo.ProfileName, obj, NET_PROFILE_NAME_LEN_MAX);

			switch(device_type) {
			case NET_DEVICE_WIFI:
				g_strlcpy(ProfInfo.ProfileInfo.Wlan.net_info.ProfileName,
						obj, NET_PROFILE_NAME_LEN_MAX);

				Error = __net_extract_wifi_info(next, &ProfInfo);
				break;
			case NET_DEVICE_CELLULAR:
				g_strlcpy(ProfInfo.ProfileInfo.Pdp.net_info.ProfileName,
						obj, NET_PROFILE_NAME_LEN_MAX);

				Error = __net_extract_mobile_info(next, &ProfInfo);
				break;
			case NET_DEVICE_ETHERNET:
				g_strlcpy(ProfInfo.ProfileInfo.Ethernet.net_info.ProfileName,
						obj, NET_PROFILE_NAME_LEN_MAX);

				Error = __net_extract_ethernet_info(next, &ProfInfo);
				break;
			case NET_DEVICE_BLUETOOTH:
				g_strlcpy(ProfInfo.ProfileInfo.Bluetooth.net_info.ProfileName,
						obj, NET_PROFILE_NAME_LEN_MAX);

				Error = __net_extract_bluetooth_info(next, &ProfInfo);
				break;
			default:
				NET_MEMFREE(*ProfilePtr);
				*prof_count = 0;

				Error = NET_ERR_NOT_SUPPORTED;
				goto error;
			}

			if (Error != NET_ERR_NONE) {
				NETWORK_LOG(NETWORK_ERROR,
						"Failed to extract service info");

				NET_MEMFREE(*ProfilePtr);
				*prof_count = 0;

				goto error;
			}

			*ProfilePtr = (net_profile_info_t *)realloc(*ProfilePtr,
					(count + 1) * sizeof(net_profile_info_t));
			if (*ProfilePtr == NULL) {
				NETWORK_LOG(NETWORK_ERROR, "Failed to allocate memory");
				*prof_count = 0;

				Error = NET_ERR_UNKNOWN;
				goto error;
			}

			memcpy(*ProfilePtr + count, &ProfInfo, sizeof(net_profile_info_t));
			count++;
		}
	}

	*prof_count = count;

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;

error:
	if (next)
		g_variant_iter_free(next);
	if (obj)
		g_free(obj);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_services(GVariantIter *message, net_device_t device_type,
		net_profile_info_t** profile_info, int* profile_count)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t *ProfilePtr = NULL;
	int prof_cnt = 0;
	char *service_prefix = NULL;

	*profile_count = 0;

	switch (device_type) {
	case NET_DEVICE_WIFI:
		service_prefix = CONNMAN_WIFI_SERVICE_PROFILE_PREFIX;
		break;
	case NET_DEVICE_CELLULAR:
		service_prefix = CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX;
		break;
	case NET_DEVICE_ETHERNET:
		service_prefix = CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX;
		break;
	case NET_DEVICE_BLUETOOTH:
		service_prefix = CONNMAN_BLUETOOTH_SERVICE_PROFILE_PREFIX;
		break;
	default:
		*profile_count = 0;
		*profile_info = NULL;
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NOT_SUPPORTED;
		break;
	}

	Error = __net_extract_all_services(message, device_type, service_prefix,
			&prof_cnt, &ProfilePtr);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to extract services from received message");
		*profile_count = 0;
		*profile_info = NULL;
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	*profile_count = prof_cnt;
	*profile_info = ProfilePtr;

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_ip(const gchar *value, net_addr_t *ipAddr)
{
	__NETWORK_FUNC_ENTER__;

	unsigned char *ipValue = NULL;
	char *saveptr = NULL;
	char ipString[NETPM_IPV4_STR_LEN_MAX+1];
	char* ipToken[4];

	ipValue = (unsigned char *)&(ipAddr->Data.Ipv4.s_addr);

	if (value != NULL) {
		g_strlcpy(ipString, value, NETPM_IPV4_STR_LEN_MAX+1);

		ipToken[0] = strtok_r(ipString, ".", &saveptr);

		if (ipToken[0] != NULL) {
			ipToken[1] = strtok_r(NULL, ".", &saveptr);

			if (ipToken[1] != NULL) {
				ipToken[2] = strtok_r(NULL, ".", &saveptr);

				if (ipToken[2] != NULL) {
					ipToken[3] = strtok_r(NULL, ".", &saveptr);

					if (ipToken[3] != NULL) {
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

static int __net_extract_common_info(const char *key, GVariant *variant, net_profile_info_t* ProfInfo)
{
	net_err_t Error = NET_ERR_NONE;
	const gchar *subKey = NULL;
	const gchar *value = NULL;
	net_dev_info_t* net_info = NULL;
	GVariant *var = NULL;
	GVariantIter *iter = NULL;

	if (ProfInfo->profile_type == NET_DEVICE_CELLULAR) {
		net_info = &(ProfInfo->ProfileInfo.Pdp.net_info);
	} else if (ProfInfo->profile_type == NET_DEVICE_WIFI) {
		net_info = &(ProfInfo->ProfileInfo.Wlan.net_info);
	} else if (ProfInfo->profile_type == NET_DEVICE_ETHERNET) {
		net_info = &(ProfInfo->ProfileInfo.Ethernet.net_info);
	} else if (ProfInfo->profile_type == NET_DEVICE_BLUETOOTH) {
		net_info = &(ProfInfo->ProfileInfo.Bluetooth.net_info);
	} else {
		NETWORK_LOG(NETWORK_ERROR,
				"Invalid Profile type. [%d]", ProfInfo->profile_type);
		return NET_ERR_INVALID_PARAM;
	}

	if (g_strcmp0(key, "State") == 0) {
		value = g_variant_get_string(variant, NULL);

		if (g_strcmp0(value, "idle") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_IDLE;
		else if (g_strcmp0(value, "failure") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_FAILURE;
		else if (g_strcmp0(value, "association") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_ASSOCIATION;
		else if (g_strcmp0(value, "configuration") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_CONFIGURATION;
		else if (g_strcmp0(value, "ready") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_READY;
		else if (g_strcmp0(value, "disconnect") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_DISCONNECT;
		else if (g_strcmp0(value, "online") == 0)
			ProfInfo->ProfileState = NET_STATE_TYPE_ONLINE;
		else
			ProfInfo->ProfileState = NET_STATE_TYPE_UNKNOWN;
	} else if (g_strcmp0(key, "Error") == 0) {
		value = g_variant_get_string(variant, NULL);

		if (g_strcmp0(value, "invalid-key") == 0)
			ProfInfo->ProfileErrorState = NET_STATE_ERROR_INVALID_KEY;
		else if (g_strcmp0(value, "connect-failed") == 0)
			ProfInfo->ProfileErrorState = NET_STATE_ERROR_CONNECT_FAILED;
		else if (g_strcmp0(value, "auth-failed") == 0)
			ProfInfo->ProfileErrorState = NET_STATE_ERROR_AUTH_FAILED;
		else if (g_strcmp0(value, "login-failed") == 0)
			ProfInfo->ProfileErrorState = NET_STATE_ERROR_LOGIN_FAILED;
		else if (g_strcmp0(value, "dhcp-failed") == 0)
			ProfInfo->ProfileErrorState = NET_STATE_ERROR_DHCP_FAILED;
		else if (g_strcmp0(value, "out-of-range") == 0)
			ProfInfo->ProfileErrorState = NET_STATE_ERROR_OUT_OF_RANGE;
		else if (g_strcmp0(value, "pin-missing") == 0)
			ProfInfo->ProfileErrorState = NET_STATE_ERROR_PIN_MISSING;
	} else if (g_strcmp0(key, "Favorite") == 0) {
		gboolean val = g_variant_get_boolean(variant);

		if (val)
			ProfInfo->Favourite = (char)TRUE;
		else
			ProfInfo->Favourite = (char)FALSE;
	} else if (g_strcmp0(key, "Ethernet") == 0) {
		g_variant_get(variant, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &subKey, &var)) {
			if (g_strcmp0(subKey, "Interface") == 0) {
				value = g_variant_get_string(var, NULL);

				if (value != NULL)
					g_strlcpy(net_info->DevName, value, NET_MAX_DEVICE_NAME_LEN);
			} else if (g_strcmp0(subKey, "Address") == 0) {
				value = g_variant_get_string(var, NULL);

				if (value != NULL)
					g_strlcpy(net_info->MacAddr, value, NET_MAX_MAC_ADDR_LEN);
			}
		}
		g_variant_iter_free(iter);
	} else if (g_strcmp0(key, "IPv4") == 0) {
		g_variant_get(variant, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &subKey, &var)) {
			if (g_strcmp0(subKey, "Method") == 0) {
				value = g_variant_get_string(var, NULL);

				if (g_strcmp0(value, "dhcp") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_DYNAMIC;
				else if (g_strcmp0(value, "manual") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_STATIC;
				else if (g_strcmp0(value, "fixed") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_FIXED;
				else if (g_strcmp0(value, "off") == 0)
					net_info->IpConfigType = NET_IP_CONFIG_TYPE_OFF;

			} else if (g_strcmp0(subKey, "Address") == 0) {
				value = g_variant_get_string(var, NULL);

				__net_extract_ip(value, &net_info->IpAddr);
			} else if (g_strcmp0(subKey, "Netmask") == 0) {
				value = g_variant_get_string(var, NULL);

				__net_extract_ip(value, &net_info->SubnetMask);
				net_info->BNetmask = TRUE;
			} else if (g_strcmp0(subKey, "Gateway") == 0) {
				value = g_variant_get_string(var, NULL);

				__net_extract_ip(value, &net_info->GatewayAddr);
				net_info->BDefGateway = TRUE;
			}
		}
		g_variant_iter_free(iter);
	} else if (g_strcmp0(key, "IPv4.Configuration") == 0) {
		if (net_info->IpConfigType != NET_IP_CONFIG_TYPE_DYNAMIC &&
		    net_info->IpConfigType != NET_IP_CONFIG_TYPE_STATIC &&
		    net_info->IpConfigType != NET_IP_CONFIG_TYPE_FIXED &&
		    net_info->IpConfigType != NET_IP_CONFIG_TYPE_OFF) {

			g_variant_get(variant, "a{sv}", &iter);
			while (g_variant_iter_loop(iter, "{sv}", &subKey, &var)) {
				if (g_strcmp0(subKey, "Method") == 0) {
					value = g_variant_get_string(var, NULL);

					if (g_strcmp0(value, "dhcp") == 0)
						net_info->IpConfigType = NET_IP_CONFIG_TYPE_DYNAMIC;
					else if (g_strcmp0(value, "manual") == 0)
						net_info->IpConfigType = NET_IP_CONFIG_TYPE_STATIC;
					else if (g_strcmp0(value, "fixed") == 0)
						net_info->IpConfigType = NET_IP_CONFIG_TYPE_FIXED;
					else if (g_strcmp0(value, "off") == 0)
						net_info->IpConfigType = NET_IP_CONFIG_TYPE_OFF;

				} else if (g_strcmp0(subKey, "Address") == 0 &&
				           net_info->IpAddr.Data.Ipv4.s_addr == 0) {
					value = g_variant_get_string(var, NULL);

					__net_extract_ip(value, &net_info->IpAddr);
				} else if (g_strcmp0(subKey, "Netmask") == 0 &&
				           net_info->SubnetMask.Data.Ipv4.s_addr == 0) {
					value = g_variant_get_string(var, NULL);

					__net_extract_ip(value, &net_info->SubnetMask);
					net_info->BNetmask = TRUE;
				} else if (g_strcmp0(subKey, "Gateway") == 0 &&
				           net_info->GatewayAddr.Data.Ipv4.s_addr == 0) {
					value = g_variant_get_string(var, NULL);

					__net_extract_ip(value, &net_info->GatewayAddr);
					net_info->BDefGateway = TRUE;
				}
			}
			g_variant_iter_free(iter);
		}
	} else if (g_strcmp0(key, "IPv6") == 0) {
		g_variant_get(variant, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &subKey, &var)) {
			if (g_strcmp0(subKey, "Method") == 0) {
				value = g_variant_get_string(var, NULL);

				if (g_strcmp0(value, "manual") == 0)
					net_info->IpConfigType6 = NET_IP_CONFIG_TYPE_STATIC;
				else if (g_strcmp0(value, "off") == 0)
					net_info->IpConfigType6 = NET_IP_CONFIG_TYPE_OFF;
				else if (g_strcmp0(value, "auto") == 0)
					net_info->IpConfigType6 = NET_IP_CONFIG_TYPE_AUTO_IP;

			} else if (g_strcmp0(subKey, "Address") == 0) {
				value = g_variant_get_string(var, NULL);

				inet_pton(AF_INET6, value, &net_info->IpAddr6.Data.Ipv6);
			} else if (g_strcmp0(subKey, "PrefixLength") == 0) {
				net_info->PrefixLen6 = g_variant_get_byte(var);
			} else if (g_strcmp0(subKey, "Gateway") == 0) {
				value = g_variant_get_string(var, NULL);

				inet_pton(AF_INET6, value, &net_info->GatewayAddr6.Data.Ipv6);
				net_info->BDefGateway6 = TRUE;
			} else if (g_strcmp0(subKey, "Privacy") == 0) {
				value = g_variant_get_string(var, NULL);

				if (value != NULL)
					g_strlcpy(net_info->Privacy6, value, NETPM_IPV6_MAX_PRIVACY_LEN);
			}
		}
		g_variant_iter_free(iter);
	} else if (g_strcmp0(key, "IPv6.Configuration") == 0) {
		g_variant_get(variant, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &subKey, &var)) {
			if (g_strcmp0(subKey, "Method") == 0) {
				value = g_variant_get_string(var, NULL);

				if (g_strcmp0(value, "manual") == 0)
					net_info->IpConfigType6 = NET_IP_CONFIG_TYPE_STATIC;
				else if (g_strcmp0(value, "off") == 0)
					net_info->IpConfigType6 = NET_IP_CONFIG_TYPE_OFF;
				else if (g_strcmp0(value, "auto") == 0)
					net_info->IpConfigType6 = NET_IP_CONFIG_TYPE_AUTO_IP;

			} else if (g_strcmp0(subKey, "Address") == 0) {
				value = g_variant_get_string(var, NULL);

				inet_pton(AF_INET6, value, &net_info->IpAddr6.Data.Ipv6);
			} else if (g_strcmp0(subKey, "PrefixLength") == 0) {
				net_info->PrefixLen6 = g_variant_get_byte(var);
			} else if (g_strcmp0(subKey, "Gateway") == 0) {
				value = g_variant_get_string(var, NULL);

				inet_pton(AF_INET6, value, &net_info->GatewayAddr6.Data.Ipv6);
				net_info->BDefGateway6 = TRUE;
			} else if (g_strcmp0(subKey, "Privacy") == 0) {
				value = g_variant_get_string(var, NULL);

				if (value != NULL)
					g_strlcpy(net_info->Privacy6, value, NETPM_IPV6_MAX_PRIVACY_LEN);
			}
		}
		g_variant_iter_free(iter);
	} else if(g_strcmp0(key, "Nameservers") == 0) {
		int dnsCount = 0;

		g_variant_get(variant, "as", &iter);
		while (g_variant_iter_loop(iter, "s", &value)) {
			__net_extract_ip(value, &net_info->DnsAddr[dnsCount]);

			dnsCount++;
			if (dnsCount >= NET_DNS_ADDR_MAX) {
				if (NULL != value)
					g_free((gchar*)value);
				break;
			}
		}

		g_variant_iter_free(iter);

		net_info->DnsCount = dnsCount;
	} else if (g_strcmp0(key, "Nameservers.Configuration") == 0 && net_info->DnsCount == 0) {
		int dnsCount = 0;

		g_variant_get(variant, "as", &iter);
		while (g_variant_iter_loop(iter, "s", &value)) {
			__net_extract_ip(value, &net_info->DnsAddr[dnsCount]);

			dnsCount++;
			if (dnsCount >= NET_DNS_ADDR_MAX) {
				if (NULL != value)
					g_free((gchar*)value);
				break;
			}
		}
		g_variant_iter_free(iter);

		net_info->DnsCount = dnsCount;
	} else if (g_strcmp0(key, "Domains") == 0) {
	} else if (g_strcmp0(key, "Domains.Configuration") == 0) {
	} else if (g_strcmp0(key, "Proxy") == 0) {
		const gchar *url = NULL;
		gchar *servers = NULL;

		g_variant_get(variant, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &subKey, &var)) {
			if (g_strcmp0(subKey, "Method") == 0) {
				value = g_variant_get_string(var, NULL);

				if (g_strcmp0(value, "direct") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_DIRECT;
				else if (g_strcmp0(value, "auto") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_AUTO;
				else if (g_strcmp0(value, "manual") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_MANUAL;
				else
					net_info->ProxyMethod = NET_PROXY_TYPE_UNKNOWN;
			} else if (g_strcmp0(subKey, "URL") == 0) {
				url = g_variant_get_string(var, NULL);
			} else if (g_strcmp0(subKey, "Servers") == 0) {
				GVariantIter *iter_sub = NULL;

				g_variant_get(var, "as", &iter_sub);
				g_variant_iter_loop(iter_sub, "s", &servers);
				g_variant_iter_free(iter_sub);
			}
		}
		g_variant_iter_free(iter);

		if (net_info->ProxyMethod == NET_PROXY_TYPE_AUTO && url != NULL)
			g_strlcpy(net_info->ProxyAddr, url, NET_PROXY_LEN_MAX);
		else if (net_info->ProxyMethod == NET_PROXY_TYPE_MANUAL && servers != NULL)
			g_strlcpy(net_info->ProxyAddr, servers, NET_PROXY_LEN_MAX);

		if (servers)
			g_free(servers);
	} else if (g_strcmp0(key, "Proxy.Configuration") == 0 &&
			net_info->ProxyMethod != NET_PROXY_TYPE_AUTO &&
			net_info->ProxyMethod != NET_PROXY_TYPE_MANUAL) {

		const gchar *url = NULL;
		gchar *servers = NULL;

		g_variant_get(variant, "a{sv}", &iter);
		while (g_variant_iter_loop(iter, "{sv}", &subKey, &var)) {
			if (g_strcmp0(subKey, "Method") == 0) {
				value = g_variant_get_string(var, NULL);

				if (g_strcmp0(value, "direct") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_DIRECT;
				else if (g_strcmp0(value, "auto") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_AUTO;
				else if (g_strcmp0(value, "manual") == 0)
					net_info->ProxyMethod = NET_PROXY_TYPE_MANUAL;
				else
					net_info->ProxyMethod = NET_PROXY_TYPE_UNKNOWN;
			} else if (g_strcmp0(subKey, "URL") == 0) {
				url = g_variant_get_string(var, NULL);
			} else if (g_strcmp0(subKey, "Servers") == 0) {
				GVariantIter *iter_sub = NULL;

				g_variant_get(var, "as", &iter_sub);
				g_variant_iter_loop(iter_sub, "s", &servers);
				g_variant_iter_free(iter_sub);
			}
		}
		g_variant_iter_free(iter);

		if (net_info->ProxyMethod == NET_PROXY_TYPE_AUTO && url != NULL)
			g_strlcpy(net_info->ProxyAddr, url, NET_PROXY_LEN_MAX);
		else if (net_info->ProxyMethod == NET_PROXY_TYPE_MANUAL && servers != NULL)
			g_strlcpy(net_info->ProxyAddr, servers, NET_PROXY_LEN_MAX);

		if (servers)
			g_free(servers);
	} else if (g_strcmp0(key, "Provider") == 0) {
		/* Do noting */
	}

	return Error;
}

static wlan_eap_type_t __convert_eap_type_from_string(const char *eap_type)
{
	if (eap_type == NULL)
		return WLAN_SEC_EAP_TYPE_PEAP;
	else if (g_str_equal(eap_type, "peap") == TRUE)
		return WLAN_SEC_EAP_TYPE_PEAP;
	else if (g_str_equal(eap_type, "tls") == TRUE)
		return WLAN_SEC_EAP_TYPE_TLS;
	else if (g_str_equal(eap_type, "ttls") == TRUE)
		return WLAN_SEC_EAP_TYPE_TTLS;
	else if (g_str_equal(eap_type, "sim") == TRUE)
		return WLAN_SEC_EAP_TYPE_SIM;
	else if (g_str_equal(eap_type, "aka") == TRUE)
		return WLAN_SEC_EAP_TYPE_AKA;
	else
		return WLAN_SEC_EAP_TYPE_PEAP;
}

static wlan_eap_auth_type_t __convert_eap_auth_from_string(const char *eap_auth)
{
	if (eap_auth == NULL)
		return WLAN_SEC_EAP_AUTH_NONE;
	else if (g_str_equal(eap_auth, "NONE") == TRUE)
		return WLAN_SEC_EAP_AUTH_NONE;
	else if (g_str_equal(eap_auth, "PAP") == TRUE)
		return WLAN_SEC_EAP_AUTH_PAP;
	else if (g_str_equal(eap_auth, "MSCHAP") == TRUE)
		return WLAN_SEC_EAP_AUTH_MSCHAP;
	else if (g_str_equal(eap_auth, "MSCHAPV2") == TRUE)
		return WLAN_SEC_EAP_AUTH_MSCHAPV2;
	else if (g_str_equal(eap_auth, "GTC") == TRUE)
		return WLAN_SEC_EAP_AUTH_GTC;
	else if (g_str_equal(eap_auth, "MD5") == TRUE)
		return WLAN_SEC_EAP_AUTH_MD5;
	else
		return WLAN_SEC_EAP_AUTH_NONE;
}

static int __net_update_connected_wifi_info(net_profile_info_t* ProfInfo)
{
	static char ifname[NET_MAX_DEVICE_NAME_LEN+1] = { '\0', };
	static char interface_path[DBUS_OBJECT_PATH_MAX] = { '\0', };
	char current_bss_path[DBUS_OBJECT_PATH_MAX] = { '\0', };
	net_err_t Error = NET_ERR_NONE;
	GVariant *params = NULL;
	GVariant *reply = NULL;
	GVariant *value = NULL;
	GVariantIter *iter = NULL;
	gchar *key = NULL;
	const char *path = NULL;

	/* Get proper interface */
	if (g_strcmp0(ProfInfo->ProfileInfo.Wlan.net_info.DevName, ifname) != 0) {
		g_strlcpy(ifname, ProfInfo->ProfileInfo.Wlan.net_info.DevName,
				NET_MAX_DEVICE_NAME_LEN+1);

		params = g_variant_new("(s)", ifname);
		reply = _net_invoke_dbus_method(SUPPLICANT_SERVICE, SUPPLICANT_PATH,
				SUPPLICANT_INTERFACE, "GetInterface", params, &Error);
		if (reply == NULL) {
			ifname[0] = '\0';
			NETWORK_LOG(NETWORK_ERROR, "Failed to get Wi-Fi interface");
			return Error;
		}
		g_variant_get(reply, "(o)", &path);
		g_strlcpy(interface_path, path, DBUS_OBJECT_PATH_MAX);

		g_variant_unref(reply);
	}

	/* Get CurrentBSS object path */
	params = g_variant_new("(ss)", SUPPLICANT_IFACE_INTERFACE, "CurrentBSS");
	reply = _net_invoke_dbus_method(SUPPLICANT_SERVICE, interface_path,
			DBUS_PROPERTIES_INTERFACE, "Get", params, &Error);
	if (reply == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get CurrentBSS");
		return Error;
	}
	g_variant_get(reply, "(v)", &value);
	path = g_variant_get_string(value, NULL);
	g_strlcpy(current_bss_path, path, DBUS_OBJECT_PATH_MAX);

	g_variant_unref(value);
	g_variant_unref(reply);

	/* Get Wi-Fi information */
	params = g_variant_new("(s)", SUPPLICANT_IFACE_BSS);
	reply = _net_invoke_dbus_method(SUPPLICANT_SERVICE, current_bss_path,
			DBUS_PROPERTIES_INTERFACE, "GetAll", params, &Error);
	if (reply == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get Wi-Fi information");
		return Error;
	}
	g_variant_get(reply, "(a{sv})", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		if (g_strcmp0(key, "BSSID") == 0) {
			gsize bssid_len = 0;
			const gchar *bssid = NULL;

			bssid =
				g_variant_get_fixed_array(value, &bssid_len, sizeof(guchar));
			if (bssid_len == 6)
				snprintf(ProfInfo->ProfileInfo.Wlan.bssid, 18,
						"%02x:%02x:%02x:%02x:%02x:%02x",
						bssid[0], bssid[1], bssid[2],
						bssid[3], bssid[4], bssid[5]);

		} else if (g_strcmp0(key, "Signal") == 0) {
			ProfInfo->ProfileInfo.Wlan.Strength =
					(unsigned char)(120 + g_variant_get_int16(value));

			if (ProfInfo->ProfileInfo.Wlan.Strength > 100)
				ProfInfo->ProfileInfo.Wlan.Strength = 100;

		} else if (g_strcmp0(key, "Frequency") == 0) {
			ProfInfo->ProfileInfo.Wlan.frequency =
					(unsigned int)g_variant_get_uint16(value);

		} else if (g_strcmp0(key, "Rates") == 0) {
			GVariantIter *iter_sub = NULL;
			guint32 value_sub;

			g_variant_get(value, "au", &iter_sub);
			while (g_variant_iter_loop(iter_sub, "u", &value_sub)) {
				ProfInfo->ProfileInfo.Wlan.max_rate = (unsigned int)value_sub;
				break;
			}

			g_variant_iter_free(iter_sub);
		}
	}

	g_variant_iter_free(iter);
	g_variant_unref(reply);

	return Error;
}

static int __net_extract_wifi_info(GVariantIter *array, net_profile_info_t* ProfInfo)
{
	net_err_t Error = NET_ERR_NONE;
	net_wifi_profile_info_t *Wlan = &(ProfInfo->ProfileInfo.Wlan);
	GVariant *var = NULL;
	const gchar *key = NULL;

	__NETWORK_FUNC_ENTER__;

	while (g_variant_iter_loop(array, "{sv}", &key, &var)) {
		const gchar *value = NULL;

		if (g_strcmp0(key, "Mode") == 0) {
			value = g_variant_get_string(var, NULL);

			if (g_strcmp0(value, "managed") == 0)
				Wlan->wlan_mode = NETPM_WLAN_CONNMODE_INFRA;
			else if (g_strcmp0(value, "adhoc") == 0)
				Wlan->wlan_mode = NETPM_WLAN_CONNMODE_ADHOC;
			else
				Wlan->wlan_mode = NETPM_WLAN_CONNMODE_AUTO;

		} else if (g_strcmp0(key, "Security") == 0) {
			GVariantIter *iter_sub = NULL;

			g_variant_get(var, "as", &iter_sub);
			while (g_variant_iter_loop(iter_sub, "s", &value)) {
				if (g_strcmp0(value, "none") == 0 &&
					Wlan->security_info.sec_mode < WLAN_SEC_MODE_NONE)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_NONE;
				else if (g_strcmp0(value, "wep") == 0 &&
						 Wlan->security_info.sec_mode < WLAN_SEC_MODE_WEP)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WEP;
				else if (g_strcmp0(value, "psk") == 0 &&
						 Wlan->security_info.sec_mode < WLAN_SEC_MODE_WPA_PSK)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WPA_PSK;
				else if (g_strcmp0(value, "ieee8021x") == 0 &&
						 Wlan->security_info.sec_mode < WLAN_SEC_MODE_IEEE8021X)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_IEEE8021X;
				else if (g_strcmp0(value, "wpa") == 0 &&
						 Wlan->security_info.sec_mode < WLAN_SEC_MODE_WPA_PSK)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WPA_PSK;
				else if (g_strcmp0(value, "rsn") == 0 &&
						 Wlan->security_info.sec_mode < WLAN_SEC_MODE_WPA_PSK)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_WPA2_PSK;
				else if (g_strcmp0(value, "wps") == 0)
					Wlan->security_info.wps_support = TRUE;
				else if (Wlan->security_info.sec_mode < WLAN_SEC_MODE_NONE)
					Wlan->security_info.sec_mode = WLAN_SEC_MODE_NONE;
			}
			g_variant_iter_free(iter_sub);
		} else if (g_strcmp0(key, "EncryptionMode") == 0) {
			value = g_variant_get_string(var, NULL);

			if (g_strcmp0(value, "none") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_NONE;
			else if (g_strcmp0(value, "wep") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_WEP;
			else if (g_strcmp0(value, "tkip") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_TKIP;
			else if (g_strcmp0(value, "aes") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_AES;
			else if (g_strcmp0(value, "mixed") == 0)
				Wlan->security_info.enc_mode = WLAN_ENC_MODE_TKIP_AES_MIXED;

		} else if (g_strcmp0(key, "Passpoint") == 0) {
			gboolean passpoint;

			passpoint = g_variant_get_boolean(var);
			if (passpoint)
				Wlan->passpoint = TRUE;
			else
				Wlan->passpoint = FALSE;

		} else if (g_strcmp0(key, "Strength") == 0) {
			Wlan->Strength = g_variant_get_byte(var);
		} else if (g_strcmp0(key, "Name") == 0) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->essid, value, NET_WLAN_ESSID_LEN);
		} else if (g_strcmp0(key, "Passphrase") == 0) {
			wlan_security_info_t *security_info = &(Wlan->security_info);
			value = g_variant_get_string(var, NULL);

			if (security_info->sec_mode == WLAN_SEC_MODE_WEP && value != NULL)
				g_strlcpy(security_info->authentication.wep.wepKey,
						value, NETPM_WLAN_MAX_WEP_KEY_LEN+1);
			else if ((security_info->sec_mode == WLAN_SEC_MODE_WPA_PSK ||
						security_info->sec_mode == WLAN_SEC_MODE_WPA2_PSK) &&
						value != NULL)
				g_strlcpy(security_info->authentication.psk.pskKey,
						value, NETPM_WLAN_MAX_PSK_PASSPHRASE_LEN+1);
		} else if (g_strcmp0(key, "PassphraseRequired") == 0) {
			gboolean val;

			val = g_variant_get_boolean(var);

			if (val)
				Wlan->PassphraseRequired = TRUE;
			else
				Wlan->PassphraseRequired = FALSE;
		} else if (g_strcmp0(key, "BSSID") == 0) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->bssid, value, NET_MAX_MAC_ADDR_LEN);

		} else if (g_strcmp0(key, "MaxRate") == 0) {
			Wlan->max_rate = (unsigned int)g_variant_get_uint32(var);

		} else if (g_strcmp0(key, "Frequency") == 0) {
			Wlan->frequency = (unsigned int)g_variant_get_uint16(var);

		} else if (g_str_equal(key, "EAP") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				Wlan->security_info.authentication.eap.eap_type =
						__convert_eap_type_from_string(value);

		} else if (g_str_equal(key, "Phase2") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				Wlan->security_info.authentication.eap.eap_auth =
						__convert_eap_auth_from_string(value);

		} else if (g_str_equal(key, "Identity") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->security_info.authentication.eap.username,
						value, NETPM_WLAN_USERNAME_LEN+1);

		} else if (g_str_equal(key, "Password") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->security_info.authentication.eap.password,
						value, NETPM_WLAN_PASSWORD_LEN+1);

		} else if (g_str_equal(key, "CACertFile") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->security_info.authentication.eap.ca_cert_filename,
						value, NETPM_WLAN_CA_CERT_FILENAME_LEN+1);

		} else if (g_str_equal(key, "ClientCertFile") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->security_info.authentication.eap.client_cert_filename,
						value, NETPM_WLAN_CLIENT_CERT_FILENAME_LEN+1);

		} else if (g_str_equal(key, "PrivateKeyFile") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->security_info.authentication.eap.private_key_filename,
						value, NETPM_WLAN_PRIVATE_KEY_FILENAME_LEN+1);

		} else if (g_str_equal(key, "PrivateKeyPassphrase") == TRUE) {
			value = g_variant_get_string(var, NULL);

			if (value != NULL)
				g_strlcpy(Wlan->security_info.authentication.eap.private_key_passwd,
						value, NETPM_WLAN_PRIVATE_KEY_PASSWD_LEN+1);
		} else
			Error = __net_extract_common_info(key, var, ProfInfo);
	}

	/* If there are multiple Wi-Fi networks which have the same SSID,
	 * and one of them is connected, we need to get the connected one
	 * rather than ConnMan grouped properties.
	 */
	if (ProfInfo->ProfileState == NET_STATE_TYPE_READY ||
			ProfInfo->ProfileState == NET_STATE_TYPE_ONLINE)
		Error = __net_update_connected_wifi_info(ProfInfo);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_mobile_info(GVariantIter *array, net_profile_info_t *ProfInfo)
{
	net_err_t Error = NET_ERR_NONE;
	GVariant *var = NULL;
	const gchar *key = NULL;

	__NETWORK_FUNC_ENTER__;

	while (g_variant_iter_loop(array, "{sv}", &key, &var)) {
		const gchar *value = NULL;

		if (g_strcmp0(key, "Mode") == 0) {
			value = g_variant_get_string(var, NULL);

			if (g_strcmp0(value, "gprs") == 0)
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_GPRS;
			else if (g_strcmp0(value, "edge") == 0)
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_EDGE;
			else if (g_strcmp0(value, "umts") == 0)
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_UMTS;
			else
				ProfInfo->ProfileInfo.Pdp.ProtocolType = NET_PDP_TYPE_NONE;
		} else if (g_strcmp0(key, "Roaming") == 0) {
			gboolean val;

			val = g_variant_get_boolean(var);
			if (val)
				ProfInfo->ProfileInfo.Pdp.Roaming = TRUE;
			else
				ProfInfo->ProfileInfo.Pdp.Roaming = FALSE;
		} else if (g_strcmp0(key, "SetupRequired") == 0) {
			gboolean val;

			val = g_variant_get_boolean(var);
			if (val)
				ProfInfo->ProfileInfo.Pdp.SetupRequired = TRUE;
			else
				ProfInfo->ProfileInfo.Pdp.SetupRequired = FALSE;
#if defined TIZEN_DUALSIM_ENABLE
		} else if (g_strcmp0(key, "Name") == 0) {
			value = g_variant_get_string(var, NULL);
			if (value != NULL) {
				gchar **list = g_strsplit(value, "/context", 0);

				if (*list) {
					g_strlcpy(ProfInfo->ProfileInfo.Pdp.PSModemPath,
								list[0], NET_PROFILE_NAME_LEN_MAX);
					NETWORK_LOG(NETWORK_LOW, "Modem path: %s",
								ProfInfo->ProfileInfo.Pdp.PSModemPath);
					g_strfreev(list);
				} else
					NETWORK_LOG(NETWORK_ERROR, "Invalid modem path: %s", value);
			} else
				NETWORK_LOG(NETWORK_ERROR, "Null modem path");
#endif
		} else
			Error = __net_extract_common_info(key, var, ProfInfo);
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

			if (strlen(telephony_profinfo.Keyword) > 0)
				g_strlcpy(ProfInfo->ProfileInfo.Pdp.Keyword,
						telephony_profinfo.Keyword,
						NET_PDP_APN_LEN_MAX);

			ProfInfo->ProfileInfo.Pdp.Hidden = telephony_profinfo.Hidden;
			ProfInfo->ProfileInfo.Pdp.Editable = telephony_profinfo.Editable;
			ProfInfo->ProfileInfo.Pdp.DefaultConn = telephony_profinfo.DefaultConn;
		}
	}

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_ethernet_info(GVariantIter *array, net_profile_info_t* ProfInfo)
{
	net_err_t Error = NET_ERR_NONE;
	GVariant *var = NULL;
	const gchar *key = NULL;

	__NETWORK_FUNC_ENTER__;

	while (g_variant_iter_loop(array, "{sv}", &key, &var))
		Error = __net_extract_common_info(key, var, ProfInfo);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_bluetooth_info(GVariantIter *array, net_profile_info_t* ProfInfo)
{
	net_err_t Error = NET_ERR_NONE;
	GVariant *var = NULL;
	const gchar *key = NULL;

	__NETWORK_FUNC_ENTER__;

	while (g_variant_iter_loop(array, "{sv}", &key, &var))
		Error = __net_extract_common_info(key, var, ProfInfo);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_extract_service_info(
		const char* ProfileName, GVariant *message,
		net_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_device_t profileType = NET_DEVICE_UNKNOWN;
	gchar *key = NULL;
	GVariantIter *iter = NULL;
	GVariant *value = NULL;

	g_variant_get(message, "(a{sv})", &iter);
	while (g_variant_iter_loop(iter, "{sv}", &key, &value)) {
		const gchar *tech = NULL;

		if (g_strcmp0(key, "Type") == 0) {
			tech = g_variant_get_string(value, NULL);

			if (g_strcmp0(tech, "wifi") == 0)
				profileType = NET_DEVICE_WIFI;
			else if (g_strcmp0(tech, "cellular") == 0)
				profileType = NET_DEVICE_CELLULAR;
			else if (g_strcmp0(tech, "ethernet") == 0)
				profileType = NET_DEVICE_ETHERNET;
			else if (g_strcmp0(tech, "bluetooth") == 0)
				profileType = NET_DEVICE_BLUETOOTH;

			g_variant_unref(value);
			g_free(key);
			break;
		}
	}
	g_variant_iter_free(iter);

	g_variant_get(message, "(a{sv})", &iter);

	if (profileType == NET_DEVICE_WIFI) {
		if ((Error = __net_pm_init_profile_info(NET_DEVICE_WIFI, ProfInfo)) != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to init profile");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		ProfInfo->profile_type = NET_DEVICE_WIFI;
		g_strlcpy(ProfInfo->ProfileName, ProfileName, NET_PROFILE_NAME_LEN_MAX);
		g_strlcpy(ProfInfo->ProfileInfo.Wlan.net_info.ProfileName,
				ProfileName, NET_PROFILE_NAME_LEN_MAX);

		Error = __net_extract_wifi_info(iter, ProfInfo);
	} else if (profileType == NET_DEVICE_CELLULAR) {
		if ((Error = __net_pm_init_profile_info(NET_DEVICE_CELLULAR, ProfInfo)) != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to init profile");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		ProfInfo->profile_type = NET_DEVICE_CELLULAR;
		g_strlcpy(ProfInfo->ProfileName, ProfileName, NET_PROFILE_NAME_LEN_MAX);
		g_strlcpy(ProfInfo->ProfileInfo.Pdp.net_info.ProfileName,
				ProfileName, NET_PROFILE_NAME_LEN_MAX);

		Error = __net_extract_mobile_info(iter, ProfInfo);
	} else if (profileType == NET_DEVICE_ETHERNET) {
		if ((Error = __net_pm_init_profile_info(NET_DEVICE_ETHERNET, ProfInfo)) != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to init profile");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		ProfInfo->profile_type = NET_DEVICE_ETHERNET;
		g_strlcpy(ProfInfo->ProfileName, ProfileName, NET_PROFILE_NAME_LEN_MAX);
		g_strlcpy(ProfInfo->ProfileInfo.Ethernet.net_info.ProfileName,
				ProfileName, NET_PROFILE_NAME_LEN_MAX);

		Error = __net_extract_ethernet_info(iter, ProfInfo);
	} else if (profileType == NET_DEVICE_BLUETOOTH) {
		if ((Error = __net_pm_init_profile_info(NET_DEVICE_BLUETOOTH, ProfInfo)) != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to init profile");
			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		ProfInfo->profile_type = NET_DEVICE_BLUETOOTH;
		g_strlcpy(ProfInfo->ProfileName, ProfileName, NET_PROFILE_NAME_LEN_MAX);
		g_strlcpy(ProfInfo->ProfileInfo.Bluetooth.net_info.ProfileName,
				ProfileName, NET_PROFILE_NAME_LEN_MAX);

		Error = __net_extract_bluetooth_info(iter, ProfInfo);
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Not supported profile type");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NOT_SUPPORTED;
	}

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to extract service information from received message");

		__NETWORK_FUNC_EXIT__;
		return Error;
	}
	g_variant_iter_free(iter);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_get_profile_info(
		const char* ProfileName, net_profile_info_t* ProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, ProfileName,
			CONNMAN_SERVICE_INTERFACE, "GetProperties", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get profile");
		goto done;
	}

	Error = __net_extract_service_info(ProfileName, message, ProfInfo);
	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_set_default_cellular_service_profile_sync(const char* ProfileName)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	net_profile_name_t telephony_profile;
	char connman_profile[NET_PROFILE_NAME_LEN_MAX+1] = "";

	g_strlcpy(connman_profile, ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	Error = __net_telephony_search_pdp_profile((char*)connman_profile, &telephony_profile);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "__net_telephony_search_pdp_profile() failed");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	message = _net_invoke_dbus_method(TELEPHONY_SERVICE, telephony_profile.ProfileName,
			TELEPHONY_PROFILE_INTERFACE, "SetDefaultConnection", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to set default cellular service(profile)");
		goto done;
	}

	/** Check Reply */
	gboolean result = FALSE;

	g_variant_get(message, "(b)", &result);
	NETWORK_LOG(NETWORK_HIGH, "Set default cellular profile result: %d", result);

	if (result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;

	return Error;
}

static int __net_set_default_cellular_service_profile_async(const char* ProfileName)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_name_t telephony_profile;
	char connman_profile[NET_PROFILE_NAME_LEN_MAX+1] = {0,};

	g_strlcpy(connman_profile, ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	Error = __net_telephony_search_pdp_profile((char*)connman_profile, &telephony_profile);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "__net_telephony_search_pdp_profile() failed");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = _net_dbus_set_default(telephony_profile.ProfileName);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_modify_wlan_profile_info(const char* ProfileName,
		net_profile_info_t* ProfInfo, net_profile_info_t* exProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	int i = 0;
	char profilePath[NET_PROFILE_NAME_LEN_MAX+1] = "";

	wlan_security_info_t *security_info =
								&(ProfInfo->ProfileInfo.Wlan.security_info);
	wlan_security_info_t *ex_security_info =
								&(exProfInfo->ProfileInfo.Wlan.security_info);

	net_dev_info_t *net_info = &(ProfInfo->ProfileInfo.Wlan.net_info);
	net_dev_info_t *ex_net_info = &(exProfInfo->ProfileInfo.Wlan.net_info);

	g_strlcpy(profilePath, ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	/* Compare and Set 'Passphrase' */
	if (ex_security_info->sec_mode == WLAN_SEC_MODE_WEP) {
		if (g_strcmp0(security_info->authentication.wep.wepKey,
						ex_security_info->authentication.wep.wepKey) != 0) {
			/* ConnMan does not support modification of passphrase only,
			 * you need to make a connection to update passphrase.
			 */
			Error = _net_dbus_set_agent_passphrase_and_connect(
					security_info->authentication.wep.wepKey, ProfileName);

			if (NET_ERR_NONE != Error) {
				NETWORK_LOG(NETWORK_ERROR, "Failed to set agent field");

				__NETWORK_FUNC_EXIT__;
				return Error;
			}
		}
	} else if (ex_security_info->sec_mode == WLAN_SEC_MODE_WPA_PSK ||
			ex_security_info->sec_mode == WLAN_SEC_MODE_WPA2_PSK) {
		if (g_strcmp0(security_info->authentication.psk.pskKey,
				ex_security_info->authentication.psk.pskKey) != 0) {
			/* ConnMan does not support modification of passphrase only,
			 * you need to make a connection to update passphrase.
			 */
			Error = _net_dbus_set_agent_passphrase_and_connect(
					security_info->authentication.psk.pskKey, ProfileName);

			if (NET_ERR_NONE != Error) {
				NETWORK_LOG(NETWORK_ERROR, "Failed to set agent field");

				__NETWORK_FUNC_EXIT__;
				return Error;
			}
		}
	}

	/* Compare and Set 'Proxy' */
	if ((ex_net_info->ProxyMethod != net_info->ProxyMethod) ||
	    (g_strcmp0(ex_net_info->ProxyAddr, net_info->ProxyAddr) != 0)) {

		Error = _net_dbus_set_proxy(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	/* Compare and Set 'IPv4 addresses' */
	if ((ex_net_info->IpConfigType != net_info->IpConfigType) ||
		(net_info->IpConfigType == NET_IP_CONFIG_TYPE_STATIC &&
		(net_info->IpAddr.Data.Ipv4.s_addr !=
								ex_net_info->IpAddr.Data.Ipv4.s_addr ||
		net_info->SubnetMask.Data.Ipv4.s_addr !=
								ex_net_info->SubnetMask.Data.Ipv4.s_addr ||
		net_info->GatewayAddr.Data.Ipv4.s_addr !=
								ex_net_info->GatewayAddr.Data.Ipv4.s_addr))) {
		Error = _net_dbus_set_profile_ipv4(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to set IPv4");

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	/* Compare and Set 'IPv6 addresses' */
	if ((ex_net_info->IpConfigType6 != net_info->IpConfigType6) ||
	    (net_info->IpConfigType6 == NET_IP_CONFIG_TYPE_STATIC &&
	     (net_info->IpAddr6.Data.Ipv6.s6_addr != ex_net_info->IpAddr6.Data.Ipv6.s6_addr ||
	      net_info->PrefixLen6 != ex_net_info->PrefixLen6 ||
	      net_info->GatewayAddr6.Data.Ipv6.s6_addr != ex_net_info->GatewayAddr6.Data.Ipv6.s6_addr))) {

		Error = _net_dbus_set_profile_ipv6(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,  "Error!!! Can't set IPv6\n");

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	/* Compare and Set 'DNS addresses' */
	for (i = 0; i < net_info->DnsCount; i++) {
		if (i >= NET_DNS_ADDR_MAX) {
			net_info->DnsCount = NET_DNS_ADDR_MAX;

			break;
		}

		if (net_info->DnsAddr[i].Data.Ipv4.s_addr !=
			ex_net_info->DnsAddr[i].Data.Ipv4.s_addr)
			break;
	}

	if (i < net_info->DnsCount) {
		Error = _net_dbus_set_profile_dns(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to set DNS\n");

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_wifi_delete_profile(net_profile_name_t* WifiProfName,
		wlan_security_mode_type_t sec_mode, gboolean passpoint)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	char param0[NET_PROFILE_NAME_LEN_MAX + 8] = "";
	GVariant *params;

	if (passpoint == TRUE && WLAN_SEC_MODE_IEEE8021X == sec_mode) {
		message = _net_invoke_dbus_method(CONNMAN_SERVICE,
				WifiProfName->ProfileName,
				CONNMAN_SERVICE_INTERFACE, "Remove", NULL,
				&Error);

		if (message == NULL) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to Remove service(profile)");
			g_variant_unref(message);
			goto done;
		}

		g_variant_unref(message);

		g_snprintf(param0, NET_PROFILE_NAME_LEN_MAX + 8, "string:%s",
				WifiProfName->ProfileName);
		params = g_variant_new("(s)", param0);

		message = _net_invoke_dbus_method(NETCONFIG_SERVICE,
				NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
				"DeleteConfig", params, &Error);
	} else if (passpoint == TRUE || WLAN_SEC_MODE_IEEE8021X != sec_mode) {
		message = _net_invoke_dbus_method(CONNMAN_SERVICE,
				WifiProfName->ProfileName,
				CONNMAN_SERVICE_INTERFACE, "Remove", NULL,
				&Error);
	} else {
		g_snprintf(param0, NET_PROFILE_NAME_LEN_MAX + 8, "string:%s",
				WifiProfName->ProfileName);
		params = g_variant_new("(s)", param0);

		message = _net_invoke_dbus_method(NETCONFIG_SERVICE,
				NETCONFIG_WIFI_PATH, NETCONFIG_WIFI_INTERFACE,
				"DeleteConfig", params, &Error);
	}

	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to Remove service(profile)");
		goto done;
	}

	g_variant_unref(message);
done:
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
		NETWORK_LOG(NETWORK_ERROR, "_net_dbus_add_pdp_profile() failed");
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

	if (_net_is_valid_service_type(exProfInfo->ProfileInfo.Pdp.ServiceType) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	g_strlcpy(connman_profile, ProfileName, NET_PROFILE_NAME_LEN_MAX+1);
	ProfInfo->ProfileInfo.Pdp.ServiceType = exProfInfo->ProfileInfo.Pdp.ServiceType;

	Error = __net_telephony_search_pdp_profile((char*)connman_profile, &telephony_profile);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "__net_telephony_search_pdp_profile() failed");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	Error = _net_dbus_modify_pdp_profile(ProfInfo, (char*)telephony_profile.ProfileName);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "_net_dbus_modify_pdp_profile() failed");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	__NETWORK_FUNC_EXIT__;

	return Error;
}

static int __net_modify_ethernet_profile(const char* ProfileName,
		net_profile_info_t* ProfInfo, net_profile_info_t* exProfInfo)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	int i = 0;
	char profilePath[NET_PROFILE_NAME_LEN_MAX+1] = "";

	net_dev_info_t *net_info = &(ProfInfo->ProfileInfo.Ethernet.net_info);
	net_dev_info_t *ex_net_info = &(exProfInfo->ProfileInfo.Ethernet.net_info);

	g_strlcpy(profilePath, ProfileName, NET_PROFILE_NAME_LEN_MAX+1);

	/* Compare and Set 'Proxy' */
	NETWORK_LOG(NETWORK_HIGH, "Proxy old:%d %s, new:%d %s\n",
			ex_net_info->ProxyMethod,
			ex_net_info->ProxyAddr,
			net_info->ProxyMethod,
			net_info->ProxyAddr);

	if ((ex_net_info->ProxyMethod != net_info->ProxyMethod) ||
		(g_strcmp0(ex_net_info->ProxyAddr, net_info->ProxyAddr) != 0)) {

		Error = _net_dbus_set_proxy(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	/* Compare and Set 'IPv4 addresses' */
	char ip_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";
	char netmask_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";
	char gateway_buffer[NETPM_IPV4_STR_LEN_MAX+1] = "";
	g_strlcpy(ip_buffer,
			inet_ntoa(ex_net_info->IpAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(netmask_buffer,
			inet_ntoa(ex_net_info->SubnetMask.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(gateway_buffer,
			inet_ntoa(ex_net_info->GatewayAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	NETWORK_LOG(NETWORK_HIGH, "IPv4 info old: type %d, IP: %s, netmask:"
			" %s, gateway: %s\n", ex_net_info->IpConfigType,
			ip_buffer,
			netmask_buffer,
			gateway_buffer);

	g_strlcpy(ip_buffer,
			inet_ntoa(net_info->IpAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(netmask_buffer,
			inet_ntoa(net_info->SubnetMask.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	g_strlcpy(gateway_buffer,
			inet_ntoa(net_info->GatewayAddr.Data.Ipv4),
			NETPM_IPV4_STR_LEN_MAX + 1);

	NETWORK_LOG(NETWORK_HIGH, "IPv4 info new: type %d, IP: %s, netmask:"
			" %s, gateway: %s\n", net_info->IpConfigType,
			ip_buffer,
			netmask_buffer,
			gateway_buffer);

	if ((ex_net_info->IpConfigType != net_info->IpConfigType) ||
		(net_info->IpConfigType == NET_IP_CONFIG_TYPE_STATIC &&
		 (net_info->IpAddr.Data.Ipv4.s_addr
		 			!= ex_net_info->IpAddr.Data.Ipv4.s_addr ||
		  net_info->SubnetMask.Data.Ipv4.s_addr
		  			!= ex_net_info->SubnetMask.Data.Ipv4.s_addr ||
		  net_info->GatewayAddr.Data.Ipv4.s_addr
		  			!= ex_net_info->GatewayAddr.Data.Ipv4.s_addr))) {
		Error = _net_dbus_set_profile_ipv4(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to set IPv4\n");

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}
	/* Compare and Set 'DNS addresses' */
	for (i = 0; i < net_info->DnsCount; i++) {
		if (i >= NET_DNS_ADDR_MAX) {
			net_info->DnsCount = NET_DNS_ADDR_MAX;
			break;
		}

		if(net_info->DnsAddr[i].Type == NET_ADDR_IPV4) {
			char old_dns[NETPM_IPV4_STR_LEN_MAX+1] = "";
			char new_dns[NETPM_IPV4_STR_LEN_MAX+1] = "";
			g_strlcpy(old_dns,
				inet_ntoa(ex_net_info->DnsAddr[i].Data.Ipv4),
				NETPM_IPV4_STR_LEN_MAX+1);
			g_strlcpy(new_dns,
				inet_ntoa(net_info->DnsAddr[i].Data.Ipv4),
				NETPM_IPV4_STR_LEN_MAX+1);

			NETWORK_LOG(NETWORK_HIGH, "IPv4 DNS Addr order: %d, old:"
				"%s, new: %s\n", i, old_dns, new_dns);

			if (net_info->DnsAddr[i].Data.Ipv4.s_addr !=
				ex_net_info->DnsAddr[i].Data.Ipv4.s_addr)
				break;
		}

	}

	if (i < net_info->DnsCount) {
		Error = _net_dbus_set_profile_dns(ProfInfo, profilePath);

		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to set DNS\n");

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

static int __net_telephony_delete_profile(net_profile_name_t* PdpProfName)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;

	message = _net_invoke_dbus_method(TELEPHONY_SERVICE, PdpProfName->ProfileName,
			TELEPHONY_PROFILE_INTERFACE, "RemoveProfile", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to Remove service(profile)");
		goto done;
	}

	/** Check Reply */
	gboolean remove_result = FALSE;

	g_variant_get(message, "(b)", &remove_result);
	NETWORK_LOG(NETWORK_HIGH, "Profile remove result: %d", remove_result);

	if (remove_result)
		Error = NET_ERR_NONE;
	else
		Error = NET_ERR_UNKNOWN;

	g_variant_unref(message);

done:
	__NETWORK_FUNC_EXIT__;
	return Error;
}

static gboolean __net_is_cellular_default_candidate(const char* profile)
{
	/* This profile should be cellular type */
	const char net_suffix[] = "_1";
	const char pre_net_suffix[] = "_3";
	const char tethering_suffix[] = "_5";
	char *suffix;

	suffix = strrchr(profile, '_');

	if (g_strcmp0(suffix, net_suffix) == 0 ||
			g_strcmp0(suffix, pre_net_suffix) == 0 ||
			g_strcmp0(suffix, tethering_suffix) == 0)
		return TRUE;

	return FALSE;
}

static int __net_extract_default_profile(
		GVariantIter *array, net_profile_info_t *ProfilePtr)
{
	net_err_t Error = NET_ERR_NONE;
	net_device_t device_type;
	gchar *key = NULL;
	GVariantIter *value = NULL;

	__NETWORK_FUNC_ENTER__;

	if (array == NULL || ProfilePtr == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	while (g_variant_iter_loop(array, "(oa{sv})", &key, &value)) {
		if (g_str_has_prefix(key, CONNMAN_CELLULAR_SERVICE_PROFILE_PREFIX) == TRUE)
			device_type = NET_DEVICE_CELLULAR;
		else if (g_str_has_prefix(key, CONNMAN_WIFI_SERVICE_PROFILE_PREFIX) == TRUE)
			device_type = NET_DEVICE_WIFI;
		else if (g_str_has_prefix(key, CONNMAN_ETHERNET_SERVICE_PROFILE_PREFIX) == TRUE)
			device_type = NET_DEVICE_ETHERNET;
		else if (g_str_has_prefix(key, CONNMAN_BLUETOOTH_SERVICE_PROFILE_PREFIX) == TRUE)
			device_type = NET_DEVICE_BLUETOOTH;
		else {
			Error = NET_ERR_NO_SERVICE;
			goto error;
		}

		Error = __net_pm_init_profile_info(device_type, ProfilePtr);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR, "Failed to init profile");
			goto error;
		}

		ProfilePtr->profile_type = device_type;
		g_strlcpy(ProfilePtr->ProfileName, key, NET_PROFILE_NAME_LEN_MAX);

		if (device_type == NET_DEVICE_CELLULAR &&
				__net_is_cellular_default_candidate(key) == TRUE) {
			g_strlcpy(ProfilePtr->ProfileInfo.Pdp.net_info.ProfileName,
					key, NET_PROFILE_NAME_LEN_MAX);

			Error = __net_extract_mobile_info(value, ProfilePtr);
			break;
		} else if (device_type == NET_DEVICE_WIFI) {
			g_strlcpy(ProfilePtr->ProfileInfo.Wlan.net_info.ProfileName,
					key, NET_PROFILE_NAME_LEN_MAX);

			Error = __net_extract_wifi_info(value, ProfilePtr);
			break;
		} else if (device_type == NET_DEVICE_ETHERNET) {
			g_strlcpy(ProfilePtr->ProfileInfo.Ethernet.net_info.ProfileName,
					key, NET_PROFILE_NAME_LEN_MAX);

			Error = __net_extract_ethernet_info(value, ProfilePtr);
			break;
		} else if (device_type == NET_DEVICE_BLUETOOTH) {
			g_strlcpy(ProfilePtr->ProfileInfo.Bluetooth.net_info.ProfileName,
					key, NET_PROFILE_NAME_LEN_MAX);

			Error = __net_extract_bluetooth_info(value, ProfilePtr);
			break;
		}
	}

	if (Error == NET_ERR_NONE &&
			(ProfilePtr->ProfileState == NET_STATE_TYPE_READY ||
					ProfilePtr->ProfileState == NET_STATE_TYPE_ONLINE))
		goto found;

	NETWORK_LOG(NETWORK_ERROR, "Fail to find default service");
	Error = NET_ERR_NO_SERVICE;

error:
	if (value)
		g_variant_iter_free(value);
	if (key)
		g_free(key);

	__NETWORK_FUNC_EXIT__;
	return Error;

found:
	NETWORK_LOG(NETWORK_HIGH, "Default: %s", ProfilePtr->ProfileName);

	if (value)
		g_variant_iter_free(value);
	if (key)
		g_free(key);

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
		NETWORK_LOG(NETWORK_ERROR, "Profile name is invalid");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	stringLen = strlen(ProfileName);

	if (strncmp(profileHeader, ProfileName, strlen(profileHeader)) == 0) {
		for (i = 0;i < stringLen;i++) {
			if (isgraph(ProfileName[i]) == 0) {
				NETWORK_LOG(NETWORK_ERROR, "Profile name is invalid");
				__NETWORK_FUNC_EXIT__;
				return NET_ERR_INVALID_PARAM;
			}
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Profile name is invalid");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}

int _net_get_profile_list(net_device_t device_type,
		net_profile_info_t** profile_info, int* profile_count)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message;
	GVariantIter *iter;

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetServices", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get service(profile) list");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	switch (device_type) {
	case NET_DEVICE_CELLULAR:
	case NET_DEVICE_WIFI:
	case NET_DEVICE_ETHERNET:
	case NET_DEVICE_BLUETOOTH:
		g_variant_get(message, "(a(oa{sv}))", &iter);
		Error = __net_extract_services(iter, device_type, profile_info, profile_count);

		if (iter != NULL)
			g_variant_iter_free(iter);
		break;

	default:
		Error = NET_ERR_UNKNOWN;
		break;
	}

	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_get_service_profile(net_service_type_t service_type, net_profile_name_t *profile_name)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	GVariantIter *iter = NULL;
	network_services_list_t service_info = { 0, };
	int i = 0;

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetServices", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get profile list");

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	Error = __net_extract_mobile_services(iter, &service_info, service_type);

	g_variant_iter_free(iter);

	if (Error != NET_ERR_NONE)
		goto done;

	if (service_info.num_of_services > 0) {
		memcpy(profile_name->ProfileName, service_info.ProfileName[0], NET_PROFILE_NAME_LEN_MAX);
		(profile_name->ProfileName)[NET_PROFILE_NAME_LEN_MAX] = '\0';
	} else
		Error = NET_ERR_NO_SERVICE;

	for (i = 0; i < service_info.num_of_services; i++)
		NET_MEMFREE(service_info.ProfileName[i]);

done:
	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

int _net_get_default_profile_info(net_profile_info_t *profile_info)
{
	net_err_t Error = NET_ERR_NONE;
	GVariant *message = NULL;
	GVariantIter *iter = NULL;

	__NETWORK_FUNC_ENTER__;

	message = _net_invoke_dbus_method(CONNMAN_SERVICE, CONNMAN_MANAGER_PATH,
			CONNMAN_MANAGER_INTERFACE, "GetServices", NULL, &Error);
	if (message == NULL) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get profile list");
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_variant_get(message, "(a(oa{sv}))", &iter);
	Error = __net_extract_default_profile(iter, profile_info);

	g_variant_iter_free (iter);
	g_variant_unref(message);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

static int __net_telephony_reset_profile(int type, int sim_id)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;

	char subscriber_id[3];
	GSList *ModemPathList = NULL;
	const char *path = NULL;
	GSList *list = NULL;

	Error = __net_telephony_get_modem_object_path(&ModemPathList);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to get modems path list");
		g_slist_free_full(ModemPathList, g_free);
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_snprintf(subscriber_id, sizeof(subscriber_id), "%d", sim_id);

	for (list = ModemPathList; list != NULL; list = list->next) {
		path = (const char *)list->data;

		if (g_str_has_suffix(path, subscriber_id) == TRUE) {
		Error = _net_dbus_reset_pdp_profile(type, path);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_HIGH, "_net_dbus_reset_pdp_profile() failed");
				break;
			}
		}
	}

	g_slist_free_full(ModemPathList, g_free);

	__NETWORK_FUNC_EXIT__;
	return NET_ERR_NONE;
}


EXPORT_API int net_reset_profile(int type, int sim_id)
{
	net_err_t Error = NET_ERR_NONE;

	__NETWORK_FUNC_ENTER__;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (request_table[NETWORK_REQUEST_TYPE_RESET_DEFAULT].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! Request already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! pending call already in progress\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	request_table[NETWORK_REQUEST_TYPE_RESET_DEFAULT].flag = TRUE;

	Error = __net_telephony_reset_profile(type, sim_id);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"Failed to reset service(profile). Error [%s]\n",
			_net_print_error(Error));
		memset(&request_table[NETWORK_REQUEST_TYPE_RESET_DEFAULT],
					0, sizeof(network_request_table_t));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

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

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (prof_info == NULL || _net_is_valid_service_type(network_type) == FALSE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_telephony_add_profile(prof_info, network_type);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Failed to add service(profile). Error [%s]",
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

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	NETWORK_LOG(NETWORK_ERROR, "Delete Profile [%s]", profile_name);

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_get_profile_info(profile_name, &prof_info);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to get service(profile) information. Error [%s]",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	g_strlcpy(wifi_prof_name.ProfileName, profile_name, NET_PROFILE_NAME_LEN_MAX + 1);

	if (prof_info.profile_type == NET_DEVICE_WIFI) {
		Error = __net_wifi_delete_profile(&wifi_prof_name,
				prof_info.ProfileInfo.Wlan.security_info.sec_mode,
				prof_info.ProfileInfo.Wlan.passpoint);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Failed to delete service(profile). Error [%s]",
					_net_print_error(Error));

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	} else if (prof_info.profile_type == NET_DEVICE_CELLULAR) {
		Error = __net_telephony_search_pdp_profile(wifi_prof_name.ProfileName, &pdp_prof_name);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Failed to get service(profile) information. Error [%s]",
					_net_print_error(Error));

			__NETWORK_FUNC_EXIT__;
			return Error;
		}

		Error = __net_telephony_delete_profile(&pdp_prof_name);
		if (Error != NET_ERR_NONE) {
			NETWORK_LOG(NETWORK_ERROR,
					"Failed to delete service(profile). Error [%s]",
					_net_print_error(Error));

			__NETWORK_FUNC_EXIT__;
			return Error;
		}
	} else {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");

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

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (prof_info == NULL ||
			_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");

		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_get_profile_info(profile_name, prof_info);
	if (Error != NET_ERR_NONE)
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to get service(profile) information. Error [%s]",
				_net_print_error(Error));

	__NETWORK_FUNC_EXIT__;
	return Error;
}

EXPORT_API int net_modify_profile(const char* profile_name, net_profile_info_t* prof_info)
{
	__NETWORK_FUNC_ENTER__;

	net_err_t Error = NET_ERR_NONE;
	net_profile_info_t exProfInfo;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	Error = net_get_profile_info(profile_name, &exProfInfo);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to get service(profile) information. Error [%s]",
				_net_print_error(Error));

		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	if (prof_info == NULL ||
	    (exProfInfo.profile_type != NET_DEVICE_WIFI &&
	     exProfInfo.profile_type != NET_DEVICE_CELLULAR &&
	     exProfInfo.profile_type != NET_DEVICE_ETHERNET)) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter\n");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (exProfInfo.profile_type == NET_DEVICE_WIFI)
		Error = __net_modify_wlan_profile_info(profile_name, prof_info, &exProfInfo);
	else if (exProfInfo.profile_type == NET_DEVICE_CELLULAR)
		Error = __net_telephony_modify_profile(profile_name, prof_info, &exProfInfo);
	else if (exProfInfo.profile_type == NET_DEVICE_ETHERNET)
		Error = __net_modify_ethernet_profile(profile_name, prof_info, &exProfInfo);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to modify service(profile) information. Error [%s]",
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
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (device_type != NET_DEVICE_CELLULAR &&
	    device_type != NET_DEVICE_WIFI &&
	    device_type != NET_DEVICE_ETHERNET &&
	    device_type != NET_DEVICE_BLUETOOTH) {
		NETWORK_LOG(NETWORK_ERROR, "Not Supported");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_NOT_SUPPORTED;
	}

	Error = _net_get_profile_list(device_type, &profile_info, &profile_count);

	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to get service(profile) list. Error [%s]",
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

EXPORT_API int net_get_cellular_modem_object_path(char **modem_path, int sim_id)
{
	net_err_t Error = NET_ERR_NONE;
	const char *path = NULL;
	char subscriber_id[3];
	GSList *ModemPathList = NULL, *list = NULL;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (sim_id < 0 || modem_path == NULL)
		return NET_ERR_INVALID_PARAM;

	Error = __net_telephony_get_modem_object_path(&ModemPathList);
	if (Error != NET_ERR_NONE)
		goto done;

	*modem_path = NULL;
	g_snprintf(subscriber_id, sizeof(subscriber_id), "%d", sim_id);
	for (list = ModemPathList; list != NULL; list = list->next) {
		path = (const char *)list->data;

		NETWORK_LOG(NETWORK_LOW, "path: %s", path);
		if (g_str_has_suffix(path, subscriber_id) == TRUE) {
			*modem_path = g_strdup(path);
			break;
		}
	}

	if (*modem_path == NULL)
		Error = NET_ERR_MODEM_INTERFACE_NOT_AVAIALABLE;
	else
		NETWORK_LOG(NETWORK_LOW, "Subscriber %d: %s", sim_id, *modem_path);

done:
	if (ModemPathList)
		g_slist_free_full(ModemPathList, g_free);

	__NETWORK_FUNC_EXIT__;
	return Error;
}

EXPORT_API int net_set_default_cellular_service_profile(const char *profile_name)
{
	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Invalid Parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	Error = __net_set_default_cellular_service_profile_sync(profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
				"Failed to set default cellular service(profile). Error [%s]",
				_net_print_error(Error));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	return NET_ERR_NONE;
}

EXPORT_API int net_set_default_cellular_service_profile_async(const char *profile_name)
{
	net_err_t Error = NET_ERR_NONE;

	if (NetworkInfo.ref_count < 1) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Application is not registered");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_APP_NOT_REGISTERED;
	}

	if (_net_check_profile_name(profile_name) != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!!! Invalid Parameter");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_INVALID_PARAM;
	}

	if (request_table[NETWORK_REQUEST_TYPE_SET_DEFAULT].flag == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! Request already in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	if (_net_dbus_is_pending_call_used() == TRUE) {
		NETWORK_LOG(NETWORK_ERROR, "Error!! pending call already in progress");
		__NETWORK_FUNC_EXIT__;
		return NET_ERR_IN_PROGRESS;
	}

	request_table[NETWORK_REQUEST_TYPE_SET_DEFAULT].flag = TRUE;

	Error = __net_set_default_cellular_service_profile_async(profile_name);
	if (Error != NET_ERR_NONE) {
		NETWORK_LOG(NETWORK_ERROR,
			"Error!!! failed to set default cellular service(profile). Error [%s]",
			_net_print_error(Error));
		memset(&request_table[NETWORK_REQUEST_TYPE_SET_DEFAULT],
					0, sizeof(network_request_table_t));
		__NETWORK_FUNC_EXIT__;
		return Error;
	}

	return NET_ERR_NONE;
}
