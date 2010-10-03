/*
* Copyright (c) 2001-2006 Nokia Corporation and/or its subsidiary(-ies).
* All rights reserved.
* This component and the accompanying materials are made available
* under the terms of the License "Eclipse Public License v1.0"
* which accompanies this distribution, and is available
* at the URL "http://www.eclipse.org/legal/epl-v10.html".
*
* Initial Contributors:
* Nokia Corporation - initial contribution.
*
* Contributors:
*
* Description:  EAP and WLAN authentication protocols.
*
*/

/*
* %version: 14 %
*/

#include "eap_am_export.h"
// Start: added by script change_export_macros.sh.
#if defined(EAP_NO_EXPORT_EAPFASTPACSTOREIMPL_H)
	#define EAP_CLASS_VISIBILITY_EAPFASTPACSTOREIMPL_H EAP_NONSHARABLE 
	#define EAP_FUNC_VISIBILITY_EAPFASTPACSTOREIMPL_H 
	#define EAP_C_FUNC_VISIBILITY_EAPFASTPACSTOREIMPL_H 
	#define EAP_FUNC_EXPORT_EAPFASTPACSTOREIMPL_H 
	#define EAP_C_FUNC_EXPORT_EAPFASTPACSTOREIMPL_H 
#elif defined(EAP_EXPORT_EAPFASTPACSTOREIMPL_H)
	#define EAP_CLASS_VISIBILITY_EAPFASTPACSTOREIMPL_H EAP_EXPORT 
	#define EAP_FUNC_VISIBILITY_EAPFASTPACSTOREIMPL_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPFASTPACSTOREIMPL_H EAP_C_FUNC_EXPORT 
	#define EAP_FUNC_EXPORT_EAPFASTPACSTOREIMPL_H EAP_FUNC_EXPORT 
	#define EAP_C_FUNC_EXPORT_EAPFASTPACSTOREIMPL_H EAP_C_FUNC_EXPORT 
#else
	#define EAP_CLASS_VISIBILITY_EAPFASTPACSTOREIMPL_H EAP_IMPORT 
	#define EAP_FUNC_VISIBILITY_EAPFASTPACSTOREIMPL_H EAP_FUNC_IMPORT 
	#define EAP_C_FUNC_VISIBILITY_EAPFASTPACSTOREIMPL_H EAP_C_FUNC_IMPORT 
	#define EAP_FUNC_EXPORT_EAPFASTPACSTOREIMPL_H 
	#define EAP_C_FUNC_EXPORT_EAPFASTPACSTOREIMPL_H 
#endif
// End: added by script change_export_macros.sh.
#include "EapFastPacStore.h"
#include "abs_eap_pac_store_message.h"
#include "eap_pac_store_message_base.h"
#include "eap_pac_store_client_message_if.h"
#include "eap_am_message_if.h"
#include "EapClientIf.h"
#include "eap_am_message_if_symbian.h"

enum eap_fast_pac_store_impl_wait_state_e
{
	eap_fast_pac_store_impl_wait_state_none,
	eap_fast_pac_store_impl_wait_state_complete_open_pac_store,
	eap_fast_pac_store_impl_wait_state_complete_create_device_seed,
	eap_fast_pac_store_impl_wait_state_complete_is_master_key_present,
	eap_fast_pac_store_impl_wait_state_complete_is_master_key_and_password_matching,
	eap_fast_pac_store_impl_wait_state_complete_create_and_save_master_key,
	eap_fast_pac_store_impl_wait_state_complete_compare_pac_store_password,
	eap_fast_pac_store_impl_wait_state_complete_is_pacstore_password_present,
	eap_fast_pac_store_impl_wait_state_complete_set_pac_store_password,
	eap_fast_pac_store_impl_wait_state_complete_destroy_pac_store,
};

class EAP_CLASS_VISIBILITY_EAPFASTPACSTOREIMPL_H CEapFastPacStoreImpl
: public CEapFastPacStore
	,public abs_eap_pac_store_message_c
{
public:
	
	static CEapFastPacStore* NewL();

	CEapFastPacStoreImpl();

	virtual ~CEapFastPacStoreImpl();

	TBool IsMasterKeyPresentL();

	TBool IsMasterKeyAndPasswordMatchingL(
		const TDesC8 & aPassword8);

	TInt CreateAndSaveMasterKeyL(
		const TDesC8 & aPassword8);

	TBool ComparePacStorePasswordL(
		TDes8 & aPassword8);

	TBool IsPacStorePasswordPresentL();

	TInt SetPacStorePasswordL(
		const TDesC8 & aPassword8);

	TInt DestroyPacStore();

	eap_status_e complete_is_master_key_present(
		bool is_present
		,const eap_status_e completion_status);

	eap_status_e complete_is_master_key_and_password_matching(
	  bool is_matching
		,const eap_status_e completion_status);

	eap_status_e complete_create_and_save_master_key(
		const eap_status_e completion_status);

	eap_status_e complete_compare_pac_store_password(
			bool is_matching);

	eap_status_e complete_is_pacstore_password_present(
			bool is_present);

	eap_status_e complete_set_pac_store_password(
		const eap_status_e completion_status);

	eap_status_e complete_destroy_pac_store(
		const eap_status_e completion_status);

	void ConstructL();

protected:


private:

	void Activate();

	void Complete();

	void WaitCompletion();

	abs_eap_am_tools_c* iTools;
	eap_pac_store_message_base_c * iPartner;
	TBool iIsValid;
	eap_fast_pac_store_impl_wait_state_e iWaitState;
	eap_status_e iCompletionStatus;
	TRequestStatus iAsyncronousStatus;
	eap_variable_data_c* iPacStorePassword;
	TBool iIsPresent;
	TBool iIsMatching;
	TBool iIsPwMatching;
	TBool iIsPwPresent;
	CActiveSchedulerWait iWait;

};