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
* %version: %
*/

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

class CEapFastPacStoreImpl
: public CEapFastPacStore
	,public abs_eap_pac_store_message_c
{
public:
	
	static CEapFastPacStore* NewL();
	
	CEapFastPacStoreImpl();
	
	virtual ~CEapFastPacStoreImpl();

	void OpenPacStoreL();
    
  void CreateDeviceSeedL();

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
  
  eap_status_e complete_open_pac_store(
		const eap_status_e completion_status);

	eap_status_e complete_create_device_seed(
		const eap_status_e completion_status);

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